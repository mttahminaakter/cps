"""Summarize three baseline/fuzzing pairs from the simulated dam lab.

Reads saved CSV files only. Does not contact Docker or send requests.
"""

import csv
import json
import math
import re
import statistics
from collections import Counter
from html import escape
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"
RUNS = {
    42: ("baseline_20261107T072409Z.csv", "multinode_20261107T072601Z.csv"),
    43: ("baseline_20261107T072729Z.csv", "multinode_20261107T072830Z.csv"),
    44: ("baseline_20261107T072926Z.csv", "multinode_20261107T072956Z.csv"),
}
NODES = ("inlet", "device")
TESTS = (
    "unit_zero", "unit_255", "length_too_small",
    "length_too_large", "unsupported_function",
)
PATTERNS = {
    "baseline": re.compile(r"^(before|after)_(inlet|device)_control_(.+)$"),
    "fuzz": re.compile(r"^(before|after)_(inlet|device)_(.+)$"),
}


def numeric(text):
    try:
        value = float(text)
        return value if math.isfinite(value) else None
    except (ValueError, TypeError):
        return None


def middle(values):
    return round(statistics.median(values), 3) if values else None


def load(path):
    if not path.exists():
        raise SystemExit(f"Missing experiment file: {path}")
    with path.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    if not rows:
        raise SystemExit(f"Empty experiment file: {path}")
    return rows


def summarize_run(rows):
    main_requests = [
        row for row in rows
        if row.get("phase") in ("baseline", "fuzz")
        and row.get("target") in NODES
    ]
    hmi_requests = [
        row for row in rows
        if row.get("target") == "hmi"
        and row.get("result", "").startswith("http_")
    ]
    monitoring = [row for row in rows if row.get("phase") == "monitor"]
    recovery = [row for row in rows if row.get("phase") == "recovery"]
    flags = Counter()
    for row in rows:
        for flag in row.get("review_flags", "").split(";"):
            if flag.strip():
                flags[flag.strip()] += 1
    status = {}
    for field in ("plc_running", "hmi_online"):
        status[field] = dict(Counter(
            (row.get(field, "") or "missing").strip().lower()
            for row in monitoring
        ))
    return {
        "main_modbus_results": dict(Counter(
            row.get("result", "unknown") for row in main_requests
        )),
        "hmi_results": dict(Counter(
            row.get("result", "unknown") for row in hmi_requests
        )),
        "monitor_snapshots": len(monitoring),
        "monitor_status": status,
        "recovery_results": dict(Counter(
            row.get("result", "unknown") for row in recovery
        )),
        "review_flags": dict(flags),
    }


def make_chart(groups, output):
    colors = (("baseline", "#64748b"), ("fuzz", "#0d9488"))
    values = [
        group[f"{condition}_median_change_ms"]
        for group in groups for condition, _ in colors
        if group[f"{condition}_median_change_ms"] is not None
    ]
    scale = max([abs(v) for v in values] + [0.1]) * 1.2
    zero = 230
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="470" viewBox="0 0 1080 470">',
        '<rect width="1080" height="470" fill="white"/>',
        '<text x="45" y="38" font-size="24" font-family="Arial">Valid-probe latency change</text>',
        '<text x="45" y="62" font-size="14" font-family="Arial">Median (after minus before), milliseconds; negative means faster</text>',
        f'<line x1="40" y1="{zero}" x2="1040" y2="{zero}" stroke="#555"/>',
        '<rect x="820" y="80" width="15" height="13" fill="#64748b"/>',
        '<text x="842" y="92" font-size="14" font-family="Arial">Baseline</text>',
        '<rect x="928" y="80" width="15" height="13" fill="#0d9488"/>',
        '<text x="950" y="92" font-size="14" font-family="Arial">Fuzzing</text>',
    ]
    for i, group in enumerate(groups):
        center = 145 + i * 260
        for dx, (condition, color) in zip((-43, 5), colors):
            value = group[f"{condition}_median_change_ms"]
            if value is None:
                continue
            shift = value / scale * 140
            top = min(zero, zero - shift)
            height = max(abs(shift), 1)
            parts.append(
                f'<rect x="{center + dx}" y="{top:.2f}" width="38" '
                f'height="{height:.2f}" fill="{color}"/>'
            )
            label_y = top - 9 if value >= 0 else top + height + 18
            parts.append(
                f'<text x="{center + dx + 19}" y="{label_y:.2f}" '
                f'text-anchor="middle" font-size="13" font-family="Arial">{value:+.3f}</text>'
            )
        label = group["fuzzed_node"].title() + " to " + group["measured_node"].title()
        parts.append(
            f'<text x="{center}" y="408" text-anchor="middle" '
            f'font-size="14" font-family="Arial">{escape(label)}</text>'
        )
    parts.append(
        '<text x="45" y="448" font-size="13" font-family="Arial">'
        'Valid requests only. Three seeded runs; these changes do not establish causation.'
        '</text>'
    )
    parts.append("</svg>")
    output.write_text("\n".join(parts), encoding="utf-8")


def main():
    observations = {}
    run_summaries = {}
    for seed, (baseline_name, fuzz_name) in RUNS.items():
        for condition, filename in (("baseline", baseline_name), ("fuzz", fuzz_name)):
            rows = load(RESULTS / filename)
            run_summaries[f"{seed}_{condition}"] = summarize_run(rows)
            for row in rows:
                if row.get("phase") != "paired_probe" or row.get("target") not in NODES:
                    continue
                match = PATTERNS[condition].fullmatch(row.get("case_id", ""))
                if not match:
                    continue
                stage, origin, test = match.groups()
                if test not in TESTS:
                    continue
                key = (seed, condition, origin, test, row["target"])
                observations.setdefault(key, {})[stage] = row

    pairs = {}
    for key, stages in observations.items():
        before = stages.get("before", {})
        after = stages.get("after", {})
        b_ms = numeric(before.get("latency_ms"))
        a_ms = numeric(after.get("latency_ms"))
        good = (b_ms is not None and a_ms is not None
                and before.get("result") == "normal_response"
                and after.get("result") == "normal_response")
        pairs[key] = {
            "before_ms": b_ms if good else None,
            "after_ms": a_ms if good else None,
            "change_ms": round(a_ms - b_ms, 6) if good else None,
        }

    matched = []
    groups = []
    for origin in NODES:
        for measured in NODES:
            group_rows = []
            for seed in RUNS:
                for test in TESTS:
                    baseline = pairs.get((seed, "baseline", origin, test, measured), {})
                    fuzz = pairs.get((seed, "fuzz", origin, test, measured), {})
                    baseline_change = baseline.get("change_ms")
                    fuzz_change = fuzz.get("change_ms")
                    complete = baseline_change is not None and fuzz_change is not None
                    row = {
                        "seed": seed, "fuzzed_node": origin, "test_case": test,
                        "measured_node": measured,
                        "baseline_before_ms": baseline.get("before_ms", ""),
                        "baseline_after_ms": baseline.get("after_ms", ""),
                        "baseline_change_ms": baseline_change if baseline_change is not None else "",
                        "fuzz_before_ms": fuzz.get("before_ms", ""),
                        "fuzz_after_ms": fuzz.get("after_ms", ""),
                        "fuzz_change_ms": fuzz_change if fuzz_change is not None else "",
                        "excess_change_ms": round(fuzz_change - baseline_change, 6) if complete else "",
                        "complete": complete,
                    }
                    matched.append(row)
                    group_rows.append(row)
            valid = [row for row in group_rows if row["complete"]]
            groups.append({
                "fuzzed_node": origin,
                "measured_node": measured,
                "complete_matches": len(valid),
                "expected_matches": len(group_rows),
                "baseline_median_change_ms": middle([x["baseline_change_ms"] for x in valid]),
                "fuzz_median_change_ms": middle([x["fuzz_change_ms"] for x in valid]),
                "median_excess_change_ms": middle([x["excess_change_ms"] for x in valid]),
            })

    csv_out = RESULTS / "final_comparison_pairs.csv"
    with csv_out.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(matched[0]))
        writer.writeheader()
        writer.writerows(matched)

    summary = {
        "seeds": list(RUNS),
        "matched_comparisons": len(matched),
        "complete_comparisons": sum(x["complete"] for x in matched),
        "groups": groups,
        "runs": run_summaries,
        "interpretation_note": (
            "Compare only valid before/after probes. These are separate sequential "
            "runs, so differences are descriptive, not causal evidence."
        ),
    }
    json_out = RESULTS / "final_comparison_summary.json"
    json_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    chart_out = RESULTS / "final_comparison_chart.svg"
    make_chart(groups, chart_out)

    report = [
        "# Baseline vs. traditional fuzzing: three-run comparison", "",
        "Seeds: 42, 43, 44. Only matching valid Modbus read probes are compared.", "",
        f"Complete matched comparisons: {summary['complete_comparisons']}/{len(matched)}.", "",
        "| Fuzzed node | Measured node | Baseline median change (ms) | Fuzz median change (ms) | Median excess change (ms) |",
        "|---|---|---:|---:|---:|",
    ]
    for group in groups:
        report.append(
            f"| {group['fuzzed_node']} | {group['measured_node']} | "
            f"{group['baseline_median_change_ms']} | {group['fuzz_median_change_ms']} | "
            f"{group['median_excess_change_ms']} |"
        )
    report += [
        "", "## Run-by-run outcomes and system monitoring", "",
        "| Seed | Condition | Normal Modbus | Exceptions | Timeouts | Closed | HMI 200 | HMI 404 | PLC available / snapshots | HMI available / snapshots | Recovery OK | Review flags |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for seed in RUNS:
        for condition in ("baseline", "fuzz"):
            details = run_summaries[f"{seed}_{condition}"]
            req = details["main_modbus_results"]
            hmi = details["hmi_results"]
            statuses = details["monitor_status"]
            flags_count = sum(details["review_flags"].values())
            report.append(
                f"| {seed} | {condition} | {req.get('normal_response', 0)} | "
                f"{req.get('modbus_exception', 0)} | {req.get('timeout', 0)} | "
                f"{req.get('connection_closed', 0)} | {hmi.get('http_200', 0)} | "
                f"{hmi.get('http_404', 0)} | "
                f"{statuses['plc_running'].get('true', 0)} / {details['monitor_snapshots']} | "
                f"{statuses['hmi_online'].get('true', 0)} / {details['monitor_snapshots']} | "
                f"{details['recovery_results'].get('recovery_ok', 0)} | {flags_count} |"
            )
    report += [
        "", "## Meaning of excess change", "",
        "For each matching case, excess change = (fuzz after - fuzz before) "
        "- (baseline after - baseline before). The table reports its median.",
        "Positive values indicate greater latency increases than the control for those pairs; "
        "negative values indicate lower increases or larger decreases.",
        "", "## Limitations", "",
        "Modbus exceptions, malformed-request timeouts, and HTTP 404 responses are not "
        "automatically security vulnerabilities. Recovery success shows the next valid probe "
        "worked, not that no transient interruption occurred. "
        "Only three sequential seeded pairs were observed; no causal or statistical "
        "significance claim is justified.", "",
    ]
    md_out = RESULTS / "final_comparison_report.md"
    md_out.write_text("\n".join(report), encoding="utf-8")

    print("\nV5 FINAL COMPARISON")
    print("Paired valid comparisons:", summary["complete_comparisons"], "/", len(matched))
    for group in groups:
        print(
            f"{group['fuzzed_node']} -> {group['measured_node']}: "
            f"baseline {group['baseline_median_change_ms']} ms, "
            f"fuzz {group['fuzz_median_change_ms']} ms, "
            f"excess {group['median_excess_change_ms']} ms"
        )
    print("\nRUN-LEVEL CHECKS")
    for seed in RUNS:
        for condition in ("baseline", "fuzz"):
            data = run_summaries[f"{seed}_{condition}"]
            print(
                f"Seed {seed} {condition}: Modbus={data['main_modbus_results']} "
                f"HMI={data['hmi_results']} recovery={data['recovery_results']} "
                f"review_flags={data['review_flags']}"
            )
    print("\nResults:", csv_out)
    print("Summary:", json_out)
    print("Report:", md_out)
    print("Chart:", chart_out)


if __name__ == "__main__":
    main()
