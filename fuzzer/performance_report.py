
"""V4: Analyze traditional fuzzing performance.

Usage:
python3 fuzzer/performance_report.py fuzzer/results/multinode_RUN.csv

This program only reads saved experiment results.
"""

import csv
import json
import re
import statistics
import sys

from collections import Counter, defaultdict
from html import escape
from pathlib import Path


PATTERN = re.compile(
    r"^(before|after)_(inlet|device)_(.+)$"
)

NODES = ("inlet", "device")


def number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def median(values):
    if not values:
        return None

    return round(statistics.median(values), 3)


def main(source):

    # STEP 1: Read the experiment CSV.

    with source.open(
        newline="", encoding="utf-8"
    ) as handle:

        reader = csv.DictReader(handle)

        required = {
            "phase", "target", "case_id",
            "result", "latency_ms"
        }

        if not required.issubset(reader.fieldnames or []):
            raise ValueError(
                "Input is not a V3B fuzzing CSV"
            )

        rows = list(reader)

    # STEP 2: Find before/after measurements.

    probes = defaultdict(dict)
    monitors = defaultdict(dict)

    for row in rows:

        match = PATTERN.fullmatch(
            row.get("case_id", "")
        )

        if not match:
            continue

        stage, origin, test_name = match.groups()
        event = (origin, test_name)

        if (
            row["phase"] == "paired_probe"
            and row["target"] in NODES
        ):
            key = (origin, test_name, row["target"])
            probes[key][stage] = row

        elif row["phase"] == "monitor":
            monitors[event][stage] = row

    if not probes:
        raise ValueError(
            "No paired measurements found. "
            "Use your V3B experiment CSV."
        )

    # STEP 3: Calculate differences.

    pair_rows = []

    for key, stages in sorted(probes.items()):

        origin, test_name, measured_node = key

        before = stages.get("before", {})
        after = stages.get("after", {})

        before_ms = number(
            before.get("latency_ms")
        )

        after_ms = number(
            after.get("latency_ms")
        )

        valid = (
            bool(before and after)
            and before.get("result") == "normal_response"
            and after.get("result") == "normal_response"
            and before_ms is not None
            and after_ms is not None
        )

        monitor_before = monitors[
            (origin, test_name)
        ].get("before", {})

        monitor_after = monitors[
            (origin, test_name)
        ].get("after", {})

        pair_rows.append({
            "fuzzed_node": origin,
            "test_case": test_name,
            "measured_node": measured_node,
            "relationship": (
                "same_node"
                if origin == measured_node
                else "other_node"
            ),
            "before_result": before.get(
                "result", "missing"
            ),
            "after_result": after.get(
                "result", "missing"
            ),
            "before_ms": (
                "" if before_ms is None else before_ms
            ),
            "after_ms": (
                "" if after_ms is None else after_ms
            ),
            "delta_ms": (
                round(after_ms - before_ms, 3)
                if valid else ""
            ),
            "pair_valid": valid,
            "plc_before": monitor_before.get(
                "plc_running", "missing"
            ),
            "plc_after": monitor_after.get(
                "plc_running", "missing"
            ),
            "hmi_before": monitor_before.get(
                "hmi_online", "missing"
            ),
            "hmi_after": monitor_after.get(
                "hmi_online", "missing"
            ),
            "water_level_before": monitor_before.get(
                "water_level_pct", ""
            ),
            "water_level_after": monitor_after.get(
                "water_level_pct", ""
            ),
            "gate_before": monitor_before.get(
                "gate_actual_pct", ""
            ),
            "gate_after": monitor_after.get(
                "gate_actual_pct", ""
            ),
            "inlet_before": monitor_before.get(
                "inlet_actual_pct", ""
            ),
            "inlet_after": monitor_after.get(
                "inlet_actual_pct", ""
            ),
            "monitor_flags_before": monitor_before.get(
                "review_flags", ""
            ),
            "monitor_flags_after": monitor_after.get(
                "review_flags", ""
            ),
        })

    # STEP 4: Save individual comparisons.

    pair_path = source.with_name(
        "performance_pairs_" + source.name
    )

    with pair_path.open(
        "w", newline="", encoding="utf-8"
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=list(pair_rows[0])
        )

        writer.writeheader()
        writer.writerows(pair_rows)

    # STEP 5: Summarize response times.

    groups = {}

    for origin in NODES:
        for measured in NODES:

            entries = [
                row for row in pair_rows
                if row["fuzzed_node"] == origin
                and row["measured_node"] == measured
            ]

            valid_entries = [
                row for row in entries
                if row["pair_valid"]
            ]

            group_name = (
                "fuzz_%s_measure_%s"
                % (origin, measured)
            )

            groups[group_name] = {
                "total_pairs": len(entries),
                "valid_pairs": len(valid_entries),
                "before_median_ms": median([
                    row["before_ms"]
                    for row in valid_entries
                ]),
                "after_median_ms": median([
                    row["after_ms"]
                    for row in valid_entries
                ]),
                "median_paired_change_ms": median([
                    row["delta_ms"]
                    for row in valid_entries
                ]),
            }

    # STEP 6: Analyze system monitoring.

    monitor_flags = Counter()
    unavailable = Counter()

    for event, stages in monitors.items():

        after = stages.get("after", {})

        for flag in after.get(
            "review_flags", ""
        ).split(";"):

            if flag:
                monitor_flags[flag] += 1

        for field in (
            "plc_running", "hmi_online"
        ):
            if after.get(field) != "True":
                unavailable[field] += 1

    # STEP 7: Save JSON summary.

    summary = {
        "source": str(source),
        "selected_test_events": len({(item["fuzzed_node"], item["test_case"]) for item in pair_rows}),
        "response_time_pairs": len(pair_rows),
        "valid_response_time_pairs": sum(
            row["pair_valid"]
            for row in pair_rows
        ),
        "groups": groups,
        "post_test_monitor_flags": dict(
            monitor_flags
        ),
        "unavailable_or_missing_post_test_status": dict(
            unavailable
        ),
        "limitation": (
            "Measurements are sequential. "
            "Response-time changes alone do not "
            "prove fuzzing caused a disruption."
        ),
    }

    summary_path = source.with_name(
        "performance_summary_"
        + source.stem + ".json"
    )

    summary_path.write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8"
    )

    # STEP 8: Create an SVG chart.
    # SVG opens in a normal web browser.

    chart_groups = [
        ("inlet", "inlet", "Inlet to inlet"),
        ("inlet", "device", "Inlet to reservoir"),
        ("device", "device", "Reservoir to reservoir"),
        ("device", "inlet", "Reservoir to inlet"),
    ]

    medians = []

    for origin, measured, label in chart_groups:

        group = groups[
            "fuzz_%s_measure_%s"
            % (origin, measured)
        ]

        medians.append((
            label,
            group["before_median_ms"],
            group["after_median_ms"]
        ))

    maximum = max(
        [
            value
            for label, before, after in medians
            for value in (before, after)
            if value is not None
        ] + [1]
    ) * 1.25

    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'width="980" height="480" viewBox="0 0 980 480">',

        '<rect width="980" height="480" fill="white"/>',

        '<text x="55" y="36" font-size="23" '
        'font-family="Arial">'
        'Median Modbus Response Time</text>',

        '<text x="55" y="62" font-size="14" '
        'font-family="Arial">'
        'Before and after fuzzing (milliseconds)</text>',

        '<line x1="55" y1="365" x2="950" y2="365" '
        'stroke="#444"/>',

        '<rect x="735" y="65" width="16" height="12" '
        'fill="#64748b"/>',

        '<text x="757" y="76" font-size="14" '
        'font-family="Arial">Before</text>',

        '<rect x="840" y="65" width="16" height="12" '
        'fill="#0d9488"/>',

        '<text x="862" y="76" font-size="14" '
        'font-family="Arial">After</text>',
    ]

    for index, (label, before, after) in enumerate(medians):

        center = 145 + index * 225

        for delta_x, value, color in (
            (-45, before, "#64748b"),
            (5, after, "#0d9488"),
        ):

            if value is None:
                continue

            height = max(
                1.0, 245 * value / maximum
            )

            x = center + delta_x
            y = 365 - height

            parts.append(
                f'<rect x="{x}" y="{y:.1f}" '
                f'width="40" height="{height:.1f}" '
                f'fill="{color}"/>'
            )

            parts.append(
                f'<text x="{x + 20}" y="{y - 8:.1f}" '
                f'text-anchor="middle" font-size="13" '
                f'font-family="Arial">{value:.2f}</text>'
            )

        parts.append(
            f'<text x="{center - 1}" y="395" '
            f'text-anchor="middle" font-size="13" '
            f'font-family="Arial">{escape(label)}</text>'
        )

    parts.append(
        '<text x="55" y="447" font-size="13" '
        'font-family="Arial">'
        'Response time differences may reflect '
        'normal system variation.</text>'
    )

    parts.append("</svg>")

    chart_path = source.with_name(
        "performance_chart_"
        + source.stem + ".svg"
    )

    chart_path.write_text(
        "\n".join(parts),
        encoding="utf-8"
    )

    # STEP 9: Print results.

    print("\nV4 PERFORMANCE COMPARISON")
    print("-------------------------")

    print(
        "Selected fuzz events:",
        summary["selected_test_events"]
    )

    print(
        "Valid paired measurements:",
        summary["valid_response_time_pairs"],
        "/", len(pair_rows)
    )

    print("\nMEDIAN RESPONSE TIMES (ms)")

    for name, values in groups.items():

        print("\n", name)
        print(
            " Before:",
            values["before_median_ms"]
        )
        print(
            " After:",
            values["after_median_ms"]
        )
        print(
            " Median paired change:",
            values["median_paired_change_ms"]
        )

    print(
        "\nPost-test monitoring flags:",
        dict(monitor_flags) or "none recorded"
    )

    print(
        "Unavailable/missing PLC or HMI status:",
        dict(unavailable) or "none recorded"
    )

    print("\nPair comparisons:", pair_path)
    print("Summary:", summary_path)
    print("Chart:", chart_path)

    print(
        "\nNote: These are observations, "
        "not proof of causation."
    )


if __name__ == "__main__":

    if len(sys.argv) != 2:
        sys.exit(
            "Usage: python3 fuzzer/performance_report.py "
            "fuzzer/results/multinode_RUN.csv"
        )

    main(Path(sys.argv[1]))

