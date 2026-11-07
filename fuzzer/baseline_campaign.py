
"""V5: Normal baseline experiment for the CPS dam.

Uses the same devices, monitoring, and request pacing
as the traditional multi-node fuzzer.

All Modbus requests are read-only.
"""

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import statistics
import time

import traditional_multinode as lab


SELECTED = {
    "unit_zero",
    "unit_255",
    "length_too_small",
    "length_too_large",
    "unsupported_function"
}


def run(args):

    # Check that the Docker lab is running.
    running = lab.compose_running()
    missing = set(lab.LAB_SERVICES) - running

    if missing:
        raise SystemExit(
            "Docker lab not running: "
            + ", ".join(sorted(missing))
        )

    if lab.read_hmi("/")["http_status"] != 200:
        raise SystemExit("HMI is not responding")

    root = Path(__file__).resolve().parent.parent
    results_dir = root / "fuzzer" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )

    csv_path = results_dir / ("baseline_%s.csv" % stamp)

    json_path = results_dir / (
        "baseline_%s_summary.json" % stamp
    )

    # Discover the existing HMI endpoint.
    paths = lab.discover_hmi_paths(root)
    hmi_api, _ = lab.candidate_hmi_json(paths)

    hmi_paths = ["/", hmi_api or "/"]

    rng = random.Random(args.seed)

    counts = Counter()
    flags = Counter()

    latencies = {
        "inlet": [],
        "device": []
    }

    restarts_before = {
        svc: lab.compose_restart_count(svc)
        for svc in lab.LAB_SERVICES
    }

    started = time.monotonic()

    with csv_path.open(
        "w", newline="", encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file, fieldnames=lab.COLUMNS
        )
        writer.writeheader()

        with lab.ModbusWorker() as worker:

            # Monitor the reservoir, inlet, PLC and HMI.
            def snapshot(label):

                raw = worker.request("snapshot")["readings"]

                values, review = lab.flatten_snapshot(raw)

                running_now = lab.compose_running()
                status = lab.read_hmi("/")["http_status"]

                if "openplc" not in running_now:
                    review.append("plc_container_not_running")

                if status != 200:
                    review.append("hmi_unavailable")

                if hmi_api:
                    answer = lab.read_hmi(hmi_api)

                    try:
                        fields = lab.extract_json_fields(
                            json.loads(
                                answer["body"].decode("utf-8")
                            )
                        )
                    except (UnicodeDecodeError, ValueError):
                        fields = {}
                        review.append("hmi_api_not_readable")

                    for key in (
                        "plc_scan_counter",
                        "plc_telemetry_age_s"
                    ):
                        if key in fields:
                            values[key] = fields[key]

                    if fields.get(
                        "plc_telemetry_age_s", 0
                    ) > 5:
                        review.append("stale_plc_telemetry")

                    for key, tolerance in (
                        ("water_level_pct", 1),
                        ("gate_actual_pct", 2),
                        ("inlet_actual_pct", 2)
                    ):
                        if (
                            key in fields
                            and key in values
                            and abs(
                                fields[key] - values[key]
                            ) > tolerance
                        ):
                            review.append(
                                "hmi_modbus_difference_" + key
                            )

                lab.record_csv(
                    writer,
                    phase="monitor",
                    target="whole_system",
                    protocol="monitor",
                    case_id=label,
                    family="baseline_health",
                    result="snapshot",
                    plc_running=str(
                        "openplc" in running_now
                    ),
                    hmi_online=str(status == 200),
                    review_flags=review,
                    **values
                )

                counts["monitor/snapshot"] += 1
                flags.update(review)

                file.flush()

            # Take valid before-and-after measurements.
            def probe_pair(stage, origin, test_name):

                for measured in ("inlet", "device"):

                    reply = worker.request(
                        "fuzz",
                        case={
                            "target": measured,
                            "function": 4,
                            "address": 0,
                            "quantity": 2
                        }
                    )["data"]

                    result = reply.get(
                        "result", "unknown"
                    )

                    lab.record_csv(
                        writer,
                        phase="paired_probe",
                        target=measured,
                        protocol="modbus_tcp",
                        family="baseline_before_after",
                        case_id="%s_%s_control_%s" % (
                            stage, origin, test_name
                        ),
                        function=4,
                        address=0,
                        quantity=2,
                        result=result,
                        latency_ms=reply.get(
                            "latency_ms", ""
                        ),
                        review_flags=(
                            [] if result == "normal_response"
                            else ["probe_failed"]
                        )
                    )

                    counts[
                        "paired_probe/%s_%s" % (
                            stage, result
                        )
                    ] += 1

                    if result != "normal_response":
                        flags["probe_failed"] += 1

                snapshot(
                    "%s_%s_control_%s" % (
                        stage, origin, test_name
                    )
                )

            # ==================================
            # BEGIN NORMAL BASELINE EXPERIMENT
            # ==================================

            print("Starting read-only normal baseline")

            snapshot("before")

            for target in ("inlet", "device"):

                slots = lab.modbus_cases(
                    target, args.per_node, rng
                )

                print(
                    "Normal Modbus node %s: %d valid reads"
                    % (target, len(slots))
                )

                for offset, slot in enumerate(slots, 1):

                    paired = (
                        slot["case_name"] in SELECTED
                    )

                    if paired:
                        probe_pair(
                            "before",
                            target,
                            slot["case_name"]
                        )

                    # Valid request only.
                    case = {
                        "target": target,
                        "function": 4,
                        "address": 0,
                        "quantity": 2
                    }

                    reply = worker.request(
                        "fuzz", case=case
                    )["data"]

                    result = reply["result"]

                    lab.record_csv(
                        writer,
                        phase="baseline",
                        target=target,
                        protocol="modbus_tcp",
                        family="valid_control",
                        case_id="valid_%03d" % offset,
                        function=4,
                        address=0,
                        quantity=2,
                        result=result,
                        latency_ms=reply.get(
                            "latency_ms", ""
                        ),
                        detail=reply.get(
                            "detail", ""
                        ),
                        request_hex=reply.get(
                            "request_hex", ""
                        ),
                        response_hex=reply.get(
                            "response_hex", ""
                        ),
                        review_flags=(
                            [] if result == "normal_response"
                            else ["normal_read_failed"]
                        )
                    )

                    counts[
                        "%s/%s" % (target, result)
                    ] += 1

                    if result == "normal_response":
                        latencies[target].append(
                            reply["latency_ms"]
                        )
                    else:
                        flags["normal_read_failed"] += 1

                    if paired:
                        probe_pair(
                            "after",
                            target,
                            slot["case_name"]
                        )

                        # Match the extra probe traffic
                        # used by the fuzzing experiment.
                        for measured in ("inlet", "device"):

                            check = worker.request(
                                "fuzz",
                                case={
                                    "target": measured,
                                    "function": 4,
                                    "address": 0,
                                    "quantity": 2
                                }
                            )["data"]

                            lab.record_csv(
                                writer,
                                phase="control_probe",
                                target=measured,
                                protocol="modbus_tcp",
                                family="matched_control",
                                case_id="after_%s_control_%s"
                                % (target, slot["case_name"]),
                                function=4,
                                address=0,
                                quantity=2,
                                result=check["result"],
                                latency_ms=check.get(
                                    "latency_ms", ""
                                ),
                                response_hex=check.get(
                                    "response_hex", ""
                                ),
                                review_flags=(
                                    []
                                    if check["result"]
                                    == "normal_response"
                                    else ["control_probe_failed"]
                                )
                            )

                            counts[
                                "control_probe/" + check["result"]
                            ] += 1

                            if check["result"] != "normal_response":
                                flags["control_probe_failed"] += 1

                        snapshot(
                            "after_control_%s_%s"
                            % (target, slot["case_name"])
                        )

                    if offset % 10 == 0:
                        snapshot(
                            "after_%s_%d"
                            % (target, offset)
                        )

                    time.sleep(args.delay)

                snapshot("after_%s" % target)

            # ==================================
            # NORMAL HMI COMMUNICATION
            # ==================================

            print("HMI node: valid HTTP GET requests")

            for index in range(11):

                path = hmi_paths[index % 2]

                answer = lab.read_hmi(path)
                status = answer["http_status"]

                outcome = (
                    "http_%d" % status
                    if status else "http_connection_error"
                )

                lab.record_csv(
                    writer,
                    phase="baseline",
                    target="hmi",
                    protocol="http_get",
                    family="valid_control",
                    case_id="valid_hmi_%02d" % (index + 1),
                    result=outcome,
                    latency_ms=answer["latency_ms"],
                    http_status=status,
                    detail=answer["detail"],
                    review_flags=(
                        [] if status == 200
                        else ["hmi_control_failed"]
                    )
                )

                counts["hmi/" + outcome] += 1

                if status != 200:
                    flags["hmi_control_failed"] += 1

                time.sleep(args.delay)

            snapshot("after_hmi")
            snapshot("final")

    # ==================================
    # SAVE EXPERIMENT SUMMARY
    # ==================================

    restarts_after = {
        svc: lab.compose_restart_count(svc)
        for svc in lab.LAB_SERVICES
    }

    for svc in lab.LAB_SERVICES:

        before = restarts_before[svc]
        after = restarts_after[svc]

        if (
            before is not None
            and after is not None
            and after > before
        ):
            flags[
                "container_restarted_" + svc
            ] += after - before

    summary = {
        "condition": "valid_request_baseline",
        "seed": args.seed,
        "per_node": args.per_node,
        "delay_seconds": args.delay,
        "elapsed_seconds": round(
            time.monotonic() - started, 2
        ),
        "counts": dict(counts),
        "review_flags": dict(flags),
        "valid_read_median_ms": {
            node: (
                round(statistics.median(times), 2)
                if times else None
            )
            for node, times in latencies.items()
        },
        "restarts_before": restarts_before,
        "restarts_after": restarts_after,
        "results_csv": str(csv_path)
    }

    json_path.write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8"
    )

    print("\nBASELINE COMPLETED")
    print("Counts:", dict(counts))
    print("Review flags:", dict(flags) or "none")
    print(
        "Valid read medians (ms):",
        summary["valid_read_median_ms"]
    )
    print("CSV:", csv_path)
    print("JSON:", json_path)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Read-only CPS baseline control"
    )

    parser.add_argument(
        "--per-node", type=int, default=40
    )

    parser.add_argument(
        "--seed", type=int, default=42
    )

    parser.add_argument(
        "--delay", type=float, default=0.2
    )

    args = parser.parse_args()

    if (
        not 18 <= args.per_node <= 300
        or not 0.1 <= args.delay <= 5
    ):
        parser.error(
            "Use 18-300 tests per node "
            "and delay of 0.1-5 seconds"
        )

    run(args)

