
"""Traditional (non-adaptive) multi-node CPS dam fuzzing campaign.

Run on macOS in ~/cps, with the existing Docker Compose lab running:
    python3 fuzzer/traditional_multinode.py --per-node 40 --seed 42

The Modbus worker runs inside the EXISTING attacker container; the HMI is
probed through the host's existing 127.0.0.1:8080 forwarding. Default
campaigns are READ-ONLY. An explicit flag enables a few bounded FC06 tests.

Requires Python 3.9+ and Docker Compose. No third-party Python packages.
"""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import random
import statistics
import re
import subprocess
import sys
import time


LAB_SERVICES = ("attacker", "device", "inlet", "openplc", "hmi")

HMI_HOST, HMI_PORT = "127.0.0.1", 8080

COLUMNS = (
    "timestamp_utc", "phase", "target", "protocol", "case_id", "family",
    "function", "address", "quantity", "value", "result", "exception_code",
    "exception_name", "latency_ms", "http_status", "detail",
    "request_hex", "response_hex", "water_level_pct", "gate_actual_pct",
    "inlet_actual_pct", "inlet_inflow_milli", "plc_running", "hmi_online",
    "plc_scan_counter", "plc_telemetry_age_s", "review_flags",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def compose_running():
    """Return the running Compose services, not just reachable TCP ports."""
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--status", "running", "--services"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return set(result.stdout.split())
    except (OSError, subprocess.SubprocessError):
        return set()


def compose_restart_count(service):
    """Docker's persistent restart count, or None if unavailable."""
    try:
        ps = subprocess.run(
            ["docker", "compose", "ps", "-q", service],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )

        container_id = ps.stdout.strip()

        if not container_id:
            return None

        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.RestartCount}}", container_id],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )

        return int(result.stdout.strip())

    except (OSError, subprocess.SubprocessError, ValueError):
        return None


class ModbusWorker:
    """One persistent Docker exec, not a costly Docker exec per testcase."""

    def __init__(self):
        self.proc = None

    def __enter__(self):
        program = Path(__file__).with_name(
            "modbus_worker.py"
        ).read_text(encoding="utf-8")

        self.proc = subprocess.Popen(
            [
                "docker", "compose", "exec", "-T",
                "attacker", "python", "-u", "-c", program
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        greeting = self._read()

        if greeting.get("event") != "ready":
            raise RuntimeError(
                "Modbus worker failed: %s" % greeting
            )

        return self

    def _read(self):
        line = self.proc.stdout.readline()

        if not line:
            error = (
                self.proc.stderr.read()
                if self.proc.poll() is not None
                else ""
            )

            raise RuntimeError(
                "Docker worker terminated unexpectedly: " + error[:600]
            )

        return json.loads(line)

    def request(self, operation, **kwargs):
        self.proc.stdin.write(
            json.dumps({"operation": operation, **kwargs}) + "\n"
        )

        self.proc.stdin.flush()

        response = self._read()

        if response.get("event") == "error":
            raise RuntimeError(
                "Modbus worker error: %s" % response.get("error")
            )

        return response

    def __exit__(self, typ, value, tb):
        if self.proc is None:
            return

        try:
            if self.proc.poll() is None:
                self.request("stop")
                self.proc.wait(timeout=5)

        except Exception:
            self.proc.kill()
            self.proc.wait()

        finally:
            for stream in (
                self.proc.stdin,
                self.proc.stdout,
                self.proc.stderr
            ):
                if stream:
                    stream.close()


def read_hmi(path):
    """Only safe, bounded GET requests to the existing localhost-only HMI."""

    if (
        not path.startswith("/")
        or path.startswith("//")
        or len(path) > 2048
    ):
        raise ValueError(
            "HMI path outside allowed relative-path scope"
        )

    began = time.monotonic()

    conn = http.client.HTTPConnection(
        HMI_HOST, HMI_PORT, timeout=2
    )

    try:
        conn.request(
            "GET",
            path,
            headers={
                "Accept": "application/json, text/html, */*",
                "User-Agent": "CPS-Graduate-Fuzzer/1.0"
            }
        )

        response = conn.getresponse()
        content = response.read(16384)
        content_type = response.getheader("Content-Type", "")

        return {
            "result": "http_response",
            "http_status": response.status,
            "latency_ms": round(
                (time.monotonic() - began) * 1000, 2
            ),
            "detail": "type=%s bytes=%d sha256=%s" % (
                content_type.split(";")[0],
                len(content),
                hashlib.sha256(content).hexdigest()[:12],
            ),
            "body": content,
            "content_type": content_type,
        }

    except (OSError, http.client.HTTPException) as exc:
        return {
            "result": "http_error",
            "http_status": 0,
            "latency_ms": round(
                (time.monotonic() - began) * 1000, 2
            ),
            "detail": str(exc),
            "body": b"",
            "content_type": "",
        }

    finally:
        conn.close()


def discover_hmi_paths(repo_root):
    """Find candidate read-only API paths in the user's real HMI source."""

    candidates = set()
    directory = repo_root / "services" / "hmi"

    if directory.exists():
        count = 0

        for file in directory.rglob("*"):
            if (
                file.suffix.lower()
                not in (".py", ".js", ".html", ".ts")
                or not file.is_file()
            ):
                continue

            if count >= 30 or file.stat().st_size > 150000:
                continue

            count += 1

            text = file.read_text(
                encoding="utf-8",
                errors="replace"
            )

            pattern = (
                r"[\"']((?:/api/[a-zA-Z0-9_/-]{1,80}|"
                r"/(?:state|status|telemetry|snapshot|health|metrics)))"
                r"(?:\?[^\"']*)?[\"']"
            )

            for path in re.findall(pattern, text):
                endpoint = path.rsplit("/", 1)[-1].lower()

                read_only_hint = (
                    "state", "status", "telemetry",
                    "snapshot", "health", "metrics",
                    "read", "data", "current", "live"
                )

                if (
                    "{" not in path
                    and ".." not in path
                    and any(
                        word in endpoint
                        for word in read_only_hint
                    )
                ):
                    candidates.add(path)

    return sorted(candidates)[:10]


def modbus_cases(name, total, rng):
    """Fixed boundary corpus plus seeded mutations; NO feedback/adaptation."""

    fixed = [
        ("valid_two_registers", 4, 0, 2, {}),
        ("valid_first_register", 4, 0, 1, {}),
        ("valid_second_register", 4, 1, 1, {}),
        ("address_just_past_map", 4, 2, 1, {}),
        ("zero_quantity", 4, 0, 0, {}),
        ("max_legal_quantity", 4, 0, 125, {}),
        ("quantity_above_spec", 4, 0, 126, {}),
        ("quantity_max_uint16", 4, 0, 65535, {}),
        ("max_address", 4, 65535, 1, {}),
        ("holding_read_valid", 3, 0, 1, {}),
        ("holding_read_bad_address", 3, 2, 1, {}),
        ("holding_read_bad_quantity", 3, 0, 126, {}),
        ("unit_zero", 4, 0, 1, {"unit": 0}),
        ("unit_255", 4, 0, 1, {"unit": 255}),
        ("invalid_protocol_id", 4, 0, 1, {"proto": 1}),
        ("length_too_small", 4, 0, 1, {"length_override": 5}),
        ("length_too_large", 4, 0, 1, {"length_override": 7}),
        ("unsupported_function", 127, 0, 1, {}),
    ]

    cases = []

    for title, function, address, quantity, changes in fixed[:total]:
        cases.append({
            "target": name,
            "family": "boundary",
            "case_name": title,
            "function": function,
            "address": address,
            "quantity": quantity,
            **changes
        })

    for index in range(max(0, total - len(fixed))):
        cases.append({
            "target": name,
            "family": "seeded_random",
            "case_name": "random_%03d" % index,
            "function": rng.choice((3, 4)),
            "address": rng.choice(
                (0, 1, 2, 3, 10, 100, 65534, 65535)
            ),
            "quantity": rng.choice(
                (0, 1, 2, 3, 124, 125, 126, 65535)
            ),
        })

    return cases


def hmi_cases(paths):
    tests = [
        ("root_valid", "/", "baseline"),
        ("empty_query", "/?probe=", "http_query"),
        ("boundary_zero", "/?probe=0", "http_query"),
        ("boundary_large", "/?probe=65535", "http_query"),
        ("percent_encoded_null", "/?probe=%00", "http_query"),
        ("duplicate_parameter", "/?probe=0&probe=100", "http_query"),
        ("long_bounded_parameter", "/?probe=" + "A" * 512, "http_query"),
        ("unknown_route", "/__cps_nonexistent_path__", "http_path"),
        ("encoded_path", "/%66%75%7a%7a", "http_path"),
    ]

    for path in paths:
        tests.append((
            "hmi_api_" + path.strip("/").replace("/", "_"),
            path,
            "http_api"
        ))

        tests.append((
            "hmi_api_query_" + path.strip("/").replace("/", "_"),
            path + "?probe=%00%FF",
            "http_api"
        ))

    return tests


def expected_commands(level):
    if level > 90:
        return 100, 0

    if level > 70:
        return 75, 50

    if level >= 40:
        return 25, 100

    return 0, 100


def extract_json_fields(data):
    """Best-effort HMI JSON extraction, never assume one unverified schema."""

    candidate_keys = {
        "water_level_pct": (
            "water_level",
            "water_level_pct",
            "reported_level",
            "reservoir_level"
        ),
        "gate_actual_pct": (
            "actual_gate",
            "gate_actual",
            "gate_position"
        ),
        "inlet_actual_pct": (
            "inlet_actual",
            "inlet_position",
            "inlet_valve"
        ),
        "plc_scan_counter": (
            "scan_counter",
            "cycle_count",
            "plc_scan_count"
        ),
        "plc_telemetry_age_s": (
            "plc_age_seconds",
            "plc_telemetry_age_s",
            "seconds_since_plc_update"
        ),
    }

    found = {}

    def visit(obj, depth):
        if depth > 5:
            return

        if isinstance(obj, dict):
            for key, value in obj.items():
                for output_name, keys in candidate_keys.items():
                    if (
                        str(key).lower() in keys
                        and output_name not in found
                    ):
                        if (
                            isinstance(value, (int, float))
                            and not isinstance(value, bool)
                        ):
                            found[output_name] = float(value)

                visit(value, depth + 1)

        elif isinstance(obj, list):
            for item in obj[:10]:
                visit(item, depth + 1)

    visit(data, 0)

    return found


def candidate_hmi_json(paths):
    """A real JSON API must be observed; a guessed route is never a source."""

    for path in paths:
        result = read_hmi(path)

        if result["http_status"] != 200:
            continue

        try:
            doc = json.loads(
                result["body"].decode("utf-8")
            )

        except (ValueError, UnicodeDecodeError):
            continue

        fields = extract_json_fields(doc)

        if fields:
            return path, fields

    return None, {}


def flatten_snapshot(readings):
    details = {}
    flags = []

    device = readings.get("device", {})
    inlet = readings.get("inlet", {})

    if (
        device.get("result") != "normal_response"
        or len(device.get("values", [])) != 2
    ):
        flags.append("reservoir_read_unavailable")

    else:
        level_raw, gate = device["values"]

        details["water_level_pct"] = level_raw / 100.0
        details["gate_actual_pct"] = gate

        if not (
            0 <= level_raw <= 10000
            and 0 <= gate <= 100
        ):
            flags.append("reservoir_out_of_bounds")

    if (
        inlet.get("result") != "normal_response"
        or len(inlet.get("values", [])) != 2
    ):
        flags.append("inlet_read_unavailable")

    else:
        valve, inflow = inlet["values"]

        details["inlet_actual_pct"] = valve
        details["inlet_inflow_milli"] = inflow

        if not (
            0 <= valve <= 100
            and 0 <= inflow <= 250
        ):
            flags.append("inlet_out_of_bounds")

        elif abs(
            inflow - (250.0 * valve / 100.0)
        ) > 2:
            flags.append("inlet_flow_inconsistent")

    if all(
        k in details
        for k in (
            "water_level_pct",
            "gate_actual_pct",
            "inlet_actual_pct"
        )
    ):
        expected_gate, expected_inlet = expected_commands(
            details["water_level_pct"]
        )

        if details["gate_actual_pct"] != expected_gate:
            flags.append("gate_differs_from_current_policy")

        if details["inlet_actual_pct"] != expected_inlet:
            flags.append("inlet_differs_from_current_policy")

    return details, flags


def record_csv(writer, **data):
    row = {
        key: ""
        for key in COLUMNS
    }

    row.update({
        key: value
        for key, value in data.items()
        if key in row
    })

    row["timestamp_utc"] = utc_now()

    if isinstance(row["review_flags"], (list, tuple)):
        row["review_flags"] = ";".join(row["review_flags"])

    writer.writerow(row)


def run_campaign(args):
    repo_root = Path(__file__).resolve().parent.parent

    output_dir = (
        (repo_root / "fuzzer" / "results")
        if not args.output_dir
        else Path(args.output_dir)
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    run_id = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    csv_path = output_dir / (
        "multinode_%s.csv" % run_id
    )

    summary_path = output_dir / (
        "multinode_%s_summary.json" % run_id
    )

    rng = random.Random(args.seed)

    running = compose_running()

    if not set(LAB_SERVICES).issubset(running):
        missing = sorted(
            set(LAB_SERVICES) - running
        )

        raise RuntimeError(
            "Lab not ready. Missing running services: %s"
            % ", ".join(missing)
        )

    if read_hmi("/")["http_status"] != 200:
        raise RuntimeError(
            "HMI must be available at http://127.0.0.1:8080 before fuzzing"
        )

    discovered = discover_hmi_paths(repo_root)

    paths = sorted(
        set(discovered + args.hmi_api_path)
    )

    hmi_api, _ = candidate_hmi_json(paths)

    print(
        "HMI API paths discovered:",
        paths or "none (HTTP root and negative tests still work)"
    )

    print(
        "HMI JSON status endpoint:",
        hmi_api or "not verified; HMI-vs-Modbus values unavailable"
    )

    print(
        "Starting traditional campaign; default requests do not change actuators."
    )

    counters = Counter()
    flags_found = Counter()
    latencies = defaultdict(list)
    signatures = defaultdict(set)

    initial_snapshot = None
    last_snapshot = None

    consecutive_policy_mismatches = 0

    last_plc_scan = None
    stalled_scan_samples = 0

    restart_before = {
        svc: compose_restart_count(svc)
        for svc in LAB_SERVICES
    }

    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as fp:

        writer = csv.DictWriter(
            fp,
            fieldnames=COLUMNS
        )

        writer.writeheader()

        with ModbusWorker() as worker:

            def sample(label):
                nonlocal last_snapshot
                nonlocal initial_snapshot
                nonlocal consecutive_policy_mismatches
                nonlocal last_plc_scan
                nonlocal stalled_scan_samples

                raw = worker.request("snapshot")["readings"]

                values, flags = flatten_snapshot(raw)

                running_now = compose_running()

                hmi = read_hmi("/")

                if "openplc" not in running_now:
                    flags.append("plc_container_not_running")

                if hmi["http_status"] != 200:
                    flags.append("hmi_unavailable")

                if hmi_api:
                    api_probe = read_hmi(hmi_api)

                    try:
                        api_values = extract_json_fields(
                            json.loads(
                                api_probe["body"].decode("utf-8")
                            )
                        )

                    except (ValueError, UnicodeDecodeError):
                        api_values = {}

                    if "plc_scan_counter" in api_values:
                        scan = int(
                            api_values["plc_scan_counter"]
                        )

                        values["plc_scan_counter"] = scan

                        if last_plc_scan == scan:
                            stalled_scan_samples += 1
                        else:
                            stalled_scan_samples = 0

                        last_plc_scan = scan

                        if stalled_scan_samples >= 2:
                            flags.append(
                                "plc_scan_counter_not_advancing"
                            )

                    if "plc_telemetry_age_s" in api_values:
                        age = api_values[
                            "plc_telemetry_age_s"
                        ]

                        values["plc_telemetry_age_s"] = age

                        if age > 5.0:
                            flags.append("stale_plc_telemetry")

                    for field, tolerance in (
                        ("water_level_pct", 1.0),
                        ("gate_actual_pct", 2.0),
                        ("inlet_actual_pct", 2.0),
                    ):
                        if (
                            field in api_values
                            and field in values
                        ):
                            if abs(
                                api_values[field] - values[field]
                            ) > tolerance:
                                flags.append(
                                    "hmi_modbus_difference_%s" % field
                                )

                policy_difference = any(
                    f in flags
                    for f in (
                        "gate_differs_from_current_policy",
                        "inlet_differs_from_current_policy"
                    )
                )

                consecutive_policy_mismatches = (
                    consecutive_policy_mismatches + 1
                    if policy_difference
                    else 0
                )

                if consecutive_policy_mismatches >= 2:
                    flags.append(
                        "repeated_controller_policy_difference"
                    )

                for flag in flags:
                    flags_found[flag] += 1

                record_csv(
                    writer,
                    phase="monitor",
                    target="whole_system",
                    protocol="monitor",
                    case_id=label,
                    family="cross_node_consistency",
                    result="snapshot",
                    plc_running=str(
                        "openplc" in running_now
                    ),
                    hmi_online=str(
                        hmi["http_status"] == 200
                    ),
                    review_flags=flags,
                    **values
                )

                counters[("monitor", "snapshot")] += 1

                fp.flush()

                if initial_snapshot is None:
                    initial_snapshot = values

                last_snapshot = values

                if flags:
                    print(
                        "  MONITOR %s: %s" % (
                            label,
                            ", ".join(flags)
                        )
                    )

                return values

            # --------------------------------------------
            # NEW: AUTOMATIC CROSS-NODE RECOVERY TESTING
            # --------------------------------------------

            def check_recovery(origin, case_id, trigger):
                """After an unusual response, check both devices and system health."""

                targets = (
                    origin,
                    "device" if origin == "inlet" else "inlet"
                )

                for node in targets:
                    started = time.monotonic()
                    reply = {}

                    for attempt in range(1, 4):
                        reply = worker.request(
                            "fuzz",
                            case={
                                "target": node,
                                "function": 4,
                                "address": 0,
                                "quantity": 2,
                            }
                        )["data"]

                        if (
                            reply.get("result") == "normal_response"
                            and len(
                                reply.get("values", [])
                            ) == 2
                        ):
                            break

                        if attempt < 3:
                            time.sleep(0.2)

                    recovered = (
                        reply.get("result") == "normal_response"
                        and len(
                            reply.get("values", [])
                        ) == 2
                    )

                    elapsed_ms = round(
                        (time.monotonic() - started) * 1000,
                        2
                    )

                    outcome = (
                        "recovery_ok"
                        if recovered
                        else "recovery_failed"
                    )

                    review = (
                        []
                        if recovered
                        else ["recovery_failed_" + node]
                    )

                    record_csv(
                        writer,
                        phase="recovery",
                        target=node,
                        protocol="modbus_tcp",
                        case_id="after_" + case_id,
                        family="cross_node_recovery",
                        function=4,
                        address=0,
                        quantity=2,
                        result=outcome,
                        latency_ms=elapsed_ms,
                        detail=(
                            "origin=%s trigger=%s attempts=%d last_reply=%s"
                            % (
                                origin,
                                trigger,
                                attempt,
                                reply.get("result", "unknown")
                            )
                        ),
                        response_hex=reply.get(
                            "response_hex", ""
                        ),
                        review_flags=review
                    )

                    counters[("recovery", outcome)] += 1

                    for flag in review:
                        flags_found[flag] += 1

                # Check OpenPLC, HMI, and device consistency.
                sample(
                    "after_recovery_%s_%s" % (
                        origin,
                        case_id
                    )
                )

            # --------------------------------------------
            # START OF TRADITIONAL FUZZING CAMPAIGN
            # --------------------------------------------

            sample("before")

            for target in ("inlet", "device"):

                cases = modbus_cases(
                    target,
                    args.per_node,
                    rng
                )

                print(
                    "Modbus node %s: %d tests"
                    % (target, len(cases))
                )

                for offset, case in enumerate(cases, 1):

                    answer = worker.request(
                        "fuzz",
                        case=case
                    )

                    data = answer["data"]

                    result = data["result"]

                    counters[(target, result)] += 1

                    latencies[target].append(
                        data.get("latency_ms", 0)
                    )

                    signatures[target].add((
                        result,
                        str(data.get("exception_code", ""))
                    ))

                    review = []

                    if result in (
                        "unexpected_response",
                        "protocol_or_connection_error"
                    ):
                        review.append("review_modbus_response")

                    # Protocol rejection can be expected for malformed MBAP.
                    if (
                        case["function"] in (3, 4)
                        and case.get("proto", 0) == 0
                        and "length_override" not in case
                    ):
                        if result in (
                            "timeout",
                            "connection_closed"
                        ):
                            review.append(
                                "review_unexpected_disconnect"
                            )

                    record_csv(
                        writer,
                        phase="fuzz",
                        target=target,
                        protocol="modbus_tcp",
                        case_id=case["case_name"],
                        family=case["family"],
                        function=case["function"],
                        address=case["address"],
                        quantity=case.get("quantity", ""),
                        result=result,
                        exception_code=data.get(
                            "exception_code", ""
                        ),
                        exception_name=data.get(
                            "exception_name", ""
                        ),
                        latency_ms=data.get(
                            "latency_ms", ""
                        ),
                        detail=data.get("detail", ""),
                        request_hex=data.get(
                            "request_hex", ""
                        ),
                        response_hex=data.get(
                            "response_hex", ""
                        ),
                        review_flags=review,
                    )

                    for flag in review:
                        flags_found[flag] += 1

                    # ------------------------------------
                    # NEW: RUN RECOVERY TEST WHEN NEEDED
                    # ------------------------------------

                    if result in (
                        "timeout",
                        "connection_closed",
                        "unexpected_response",
                        "protocol_or_connection_error"
                    ):
                        check_recovery(
                            target,
                            case["case_name"],
                            result
                        )

                    if offset % 10 == 0:
                        sample(
                            "after_%s_%d"
                            % (target, offset)
                        )

                    time.sleep(args.delay)

                sample("after_%s" % target)

            # --------------------------------------------
            # HMI HTTP FUZZING
            # --------------------------------------------

            print(
                "HMI node: HTTP GET mutation campaign"
            )

            for case_id, path, family in hmi_cases(paths):

                answer = read_hmi(path)

                status = answer["http_status"]

                result = (
                    "http_%d" % status
                    if status
                    else "http_connection_error"
                )

                counters[("hmi", result)] += 1

                latencies["hmi"].append(
                    answer.get("latency_ms", 0)
                )

                signatures["hmi"].add((
                    result, ""
                ))

                review = (
                    ["http_5xx"]
                    if 500 <= status <= 599
                    else (
                        ["hmi_connection_failure"]
                        if status == 0
                        else []
                    )
                )

                for flag in review:
                    flags_found[flag] += 1

                record_csv(
                    writer,
                    phase="fuzz",
                    target="hmi",
                    protocol="http_get",
                    case_id=case_id,
                    family=family,
                    result=result,
                    latency_ms=answer["latency_ms"],
                    http_status=status,
                    detail=answer["detail"],
                    review_flags=review
                )

                time.sleep(args.delay)

            sample("after_hmi")

            # --------------------------------------------
            # OPTIONAL WRITE EXPERIMENT
            # --------------------------------------------

            if args.enable_write_experiment:
                print(
                    "OPT-IN: bounded FC06 tests on two simulated devices"
                )

                injections = (
                    ("inlet", 101),
                    ("device", 101),
                    ("inlet", 0),
                    ("device", 100)
                )

                for target, value in injections:

                    case = {
                        "target": target,
                        "function": 6,
                        "address": 0,
                        "value": value,
                        "write_opt_in": True
                    }

                    answer = worker.request(
                        "fuzz",
                        case=case
                    )["data"]

                    counters[
                        (target, answer["result"])
                    ] += 1

                    record_csv(
                        writer,
                        phase="optional_write",
                        target=target,
                        protocol="modbus_tcp",
                        case_id="fc06_%d" % value,
                        family="bounded_write",
                        function=6,
                        address=0,
                        value=value,
                        result=answer["result"],
                        exception_code=answer.get(
                            "exception_code", ""
                        ),
                        exception_name=answer.get(
                            "exception_name", ""
                        ),
                        latency_ms=answer["latency_ms"],
                        detail=answer.get("detail", ""),
                        request_hex=answer.get(
                            "request_hex", ""
                        ),
                        response_hex=answer.get(
                            "response_hex", ""
                        )
                    )

                    time.sleep(1.5)

                    sample(
                        "recovery_%s_%d"
                        % (target, value)
                    )

                sample("after_optional_writes")

            # --------------------------------------------
            # FINAL MONITORING AND RESTART CHECK
            # --------------------------------------------

            sample("final")

            restart_after = {
                svc: compose_restart_count(svc)
                for svc in LAB_SERVICES
            }

            for svc in LAB_SERVICES:

                before = restart_before.get(svc)
                after = restart_after.get(svc)

                if (
                    before is not None
                    and after is not None
                    and after > before
                ):
                    flags_found[
                        "container_restarted_" + svc
                    ] += after - before

                    record_csv(
                        writer,
                        phase="health",
                        target=svc,
                        protocol="docker",
                        case_id="container_restart_count",
                        family="resilience",
                        result="restarts_detected",
                        detail="before=%d after=%d" % (
                            before, after
                        ),
                        review_flags=[
                            "container_restarted_" + svc
                        ]
                    )

            fp.flush()

    def percentile(values, pct):
        if not values:
            return None

        ordered = sorted(values)

        index = max(
            0,
            min(
                len(ordered) - 1,
                int(
                    (len(ordered) - 1) * pct
                    + 0.999999
                )
            )
        )

        return round(
            ordered[index], 2
        )

    summary = {
        "run_id": run_id,
        "seed": args.seed,
        "per_node": args.per_node,
        "delay_seconds": args.delay,
        "write_experiment_enabled": args.enable_write_experiment,
        "hmi_source_discovered_paths": discovered,
        "hmi_api_paths_tested": paths,
        "hmi_json_endpoint_verified": hmi_api,
        "initial_snapshot": initial_snapshot,
        "final_snapshot": last_snapshot,
        "container_restarts_before": restart_before,
        "container_restarts_after": restart_after,
        "counts": {
            "%s:%s" % key: value
            for key, value in sorted(counters.items())
        },
        "review_flag_counts": dict(flags_found),
        "unique_response_signatures": {
            name: len(v)
            for name, v in signatures.items()
        },
        "latency_ms": {
            name: {
                "median": round(
                    statistics.median(v), 2
                ),
                "p95": percentile(v, 0.95)
            }
            for name, v in latencies.items()
            if v
        },
        "interpretation": (
            "Normal Modbus exceptions and HTTP 4xx "
            "do not by themselves imply vulnerabilities."
        ),
        "results_csv": str(csv_path),
    }

    summary_path.write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8"
    )

    print(
        "\nCOMPLETED (not proof of any vulnerability)"
    )

    for key, count in sorted(counters.items()):
        print(
            "  %-35s %d"
            % ("/".join(key), count)
        )

    print(
        "Review flags:",
        dict(flags_found) or "none"
    )

    print(
        "Unique response signatures:",
        summary["unique_response_signatures"]
    )

    print(
        "Response latency (ms):",
        summary["latency_ms"]
    )

    print("CSV:", csv_path)
    print("JSON summary:", summary_path)

    return 0


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Non-adaptive traditional CPS multi-node fuzzing suite"
        )
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Reproducible random seed"
    )

    parser.add_argument(
        "--per-node",
        type=int,
        default=40,
        help="Read-only Modbus tests per node (18-300)"
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Seconds between tests (min 0.1)"
    )

    parser.add_argument(
        "--hmi-api-path",
        action="append",
        default=[],
        help="Optional verified read-only HMI JSON path"
    )

    parser.add_argument(
        "--output-dir",
        help="Where to write generated CSV/JSON files"
    )

    parser.add_argument(
        "--enable-write-experiment",
        action="store_true",
        help="Explicitly opt into four bounded FC06 tests"
    )

    args = parser.parse_args()

    if not (
        18 <= args.per_node <= 300
    ):
        parser.error(
            "--per-node must be between 18 and 300"
        )

    if not (
        0.1 <= args.delay <= 5
    ):
        parser.error(
            "--delay must be between 0.1 and 5 seconds"
        )

    if any(
        not p.startswith("/")
        or p.startswith("//")
        or ".." in p
        or len(p) > 100
        for p in args.hmi_api_path
    ):
        parser.error(
            "--hmi-api-path must be a safe relative API path"
        )

    try:
        return run_campaign(args)

    except (
        RuntimeError,
        OSError,
        subprocess.SubprocessError
    ) as exc:
        print(
            "ERROR:",
            exc,
            file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())

