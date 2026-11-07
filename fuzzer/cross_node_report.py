
"""Analyze cross-node effects after traditional Modbus fuzzing."""

import csv
import sys
from pathlib import Path
from collections import Counter

UNUSUAL_RESULTS = {
    "timeout",
    "connection_closed",
    "unexpected_response",
    "protocol_or_connection_error"
}

COLUMNS = [
    "timestamp_utc",
    "source_node",
    "test_case",
    "fuzz_result",
    "inlet_recovery",
    "reservoir_recovery",
    "inlet_probe_ms",
    "reservoir_probe_ms",
    "plc_running",
    "hmi_online",
    "water_level_pct",
    "gate_actual_pct",
    "inlet_actual_pct",
    "inlet_inflow_milli",
    "plc_scan_counter",
    "plc_telemetry_age_s",
    "monitor_flags",
    "assessment"
]


def analyze(csv_path):

    with open(csv_path, newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    findings = []

    for index, row in enumerate(rows):

        if row["phase"] != "fuzz":
            continue

        if row["target"] not in ("inlet", "device"):
            continue

        if row["result"] not in UNUSUAL_RESULTS:
            continue

        # Examine records after this unusual request,
        # stopping at the next fuzz request.
        next_rows = []

        for item in rows[index + 1:]:
            if item["phase"] == "fuzz":
                break

            next_rows.append(item)

        recovery_id = "after_" + row["case_id"]

        recovery = {
            item["target"]: item
            for item in next_rows
            if item["phase"] == "recovery"
            and item["case_id"] == recovery_id
        }

        monitor_id = (
            "after_recovery_%s_%s"
            % (row["target"], row["case_id"])
        )

        monitor = next(
            (
                item for item in next_rows
                if item["phase"] == "monitor"
                and item["case_id"] == monitor_id
            ),
            None
        )

        # Determine whether all expected evidence exists.
        complete = (
            monitor is not None
            and set(recovery) == {"inlet", "device"}
        )

        if not complete:
            assessment = "incomplete_evidence"

        elif (
            all(
                recovery[node]["result"] == "recovery_ok"
                for node in ("inlet", "device")
            )
            and monitor["plc_running"] == "True"
            and monitor["hmi_online"] == "True"
            and not monitor["review_flags"]
        ):
            assessment = "no_issue_observed_at_sampling"

        else:
            assessment = "review_cross_node_behavior"

        def monitor_value(field):
            if monitor:
                return monitor.get(field, "")
            return ""

        findings.append({
            "timestamp_utc": row["timestamp_utc"],
            "source_node": row["target"],
            "test_case": row["case_id"],
            "fuzz_result": row["result"],

            "inlet_recovery": recovery.get(
                "inlet", {}
            ).get("result", "missing"),

            "reservoir_recovery": recovery.get(
                "device", {}
            ).get("result", "missing"),

            "inlet_probe_ms": recovery.get(
                "inlet", {}
            ).get("latency_ms", ""),

            "reservoir_probe_ms": recovery.get(
                "device", {}
            ).get("latency_ms", ""),

            "plc_running": monitor_value("plc_running"),
            "hmi_online": monitor_value("hmi_online"),

            "water_level_pct": monitor_value(
                "water_level_pct"
            ),

            "gate_actual_pct": monitor_value(
                "gate_actual_pct"
            ),

            "inlet_actual_pct": monitor_value(
                "inlet_actual_pct"
            ),

            "inlet_inflow_milli": monitor_value(
                "inlet_inflow_milli"
            ),

            "plc_scan_counter": monitor_value(
                "plc_scan_counter"
            ),

            "plc_telemetry_age_s": monitor_value(
                "plc_telemetry_age_s"
            ),

            "monitor_flags": monitor_value("review_flags"),
            "assessment": assessment
        })

    output_path = csv_path.with_name(
        "cross_node_" + csv_path.name
    )

    with open(
        output_path, "w", newline="", encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file, fieldnames=COLUMNS
        )

        writer.writeheader()
        writer.writerows(findings)

    print("\nCROSS-NODE IMPACT ANALYSIS")
    print("--------------------------")

    print("Unusual Modbus events:", len(findings))

    counts = Counter(
        item["assessment"] for item in findings
    )

    for result, count in sorted(counts.items()):
        print(result, ":", count)

    print("\nIndividual test results:")

    for item in findings:
        print(
            item["source_node"],
            item["test_case"],
            "->",
            item["assessment"]
        )

    print("\nReport saved:", output_path)
    print(
        "Note: Observations were collected after recovery "
        "checks. They do not establish causation."
    )


if __name__ == "__main__":

    if len(sys.argv) != 2:
        sys.exit(
            "Usage: python3 fuzzer/cross_node_report.py "
            "fuzzer/results/multinode_RUN.csv"
        )

    source = Path(sys.argv[1])

    if not source.is_file():
        sys.exit("CSV file not found: " + str(source))

    analyze(source)

