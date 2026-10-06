"""Assemble Phase 5 research tables from current-head experiment outputs."""

from __future__ import annotations

import csv
import shutil
from pathlib import Path


ROOT = Path("results/current_head")
OUT = ROOT / "research_contribution"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def mean(rows: list[dict[str, str]], field: str) -> float | None:
    values = []
    for row in rows:
        value = row.get(field)
        if value in (None, "", "nan"):
            continue
        if value.lower() == "true":
            values.append(1.0)
        elif value.lower() == "false":
            values.append(0.0)
        else:
            values.append(float(value))
    return sum(values) / len(values) if values else None


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    raw = read_csv(ROOT / "raw/baseline_comparison/runs.csv")
    security_rows: list[dict[str, object]] = []
    for variant in sorted({row["variant"] for row in raw}):
        for attack in sorted({row["kind"] for row in raw if row["variant"] == variant}):
            if attack == "benign":
                continue
            subset = [row for row in raw if row["variant"] == variant and row["kind"] == attack]
            security_rows.append({
                "attack": attack,
                "target": "D3",
                "system_variant": variant,
                "runs": len(subset),
                "detection_rate": mean(subset, "detected"),
                "detection_latency_ms_mean": mean(subset, "detection_ms"),
                "response_ms_mean": mean(subset, "response_ms"),
                "mitigation_rate_mean": mean(subset, "mitigation_rate"),
                "false_positive_rate": mean(subset, "flag_rate"),
                "collateral_rate": mean(subset, "collateral_rate"),
                "quarantine_rate": mean(subset, "quarantine_count"),
                "reauthentication_count_mean": mean(subset, "reauth_count"),
                "final_attacker_state": sorted({row["max_attacker_state"] for row in subset}),
                "limitation": "Trust/policy transition timestamps are not stored per run.",
            })
    write_csv(OUT / "security_comparison.csv", security_rows)

    ablation = read_csv(ROOT / "processed/ablation/summary.csv")
    write_csv(OUT / "ablation_results.csv", [
        {
            "variant": row["variant"],
            "runs": row["runs"],
            "detection_rate": row["detection_rate"],
            "false_positive_rate": row["fpr_flag_rate"],
            "false_negative_rate": row["fnr"],
            "mitigation_rate": row["mitigation_rate"],
            "response_ms_median": row["response_ms_median"],
            "monitor_ms_per_window": row["monitor_ms_per_window"],
            "security_bytes_per_s": row["security_bytes_per_s"],
            "interpretation": "Current-head executable ablation summary.",
        }
        for row in ablation
    ])

    trust = read_csv(ROOT / "trust_validation.csv")
    write_csv(OUT / "trust_response.csv", [
        {
            **row,
            "policy_state": (
                "normal" if float(row["trust"]) >= 0.80 else
                "monitor" if float(row["trust"]) >= 0.60 else
                "restrict" if float(row["trust"]) >= 0.40 else
                "reauthenticate" if float(row["trust"]) >= 0.20 else "quarantine"
            ),
            "attack_start_end": "controlled evidence sequence; no wall-clock attack interval",
        }
        for row in trust
    ])

    scale = read_csv(ROOT / "raw/scalability/scalability.csv")
    write_csv(OUT / "adaptive_overhead.csv", [
        {
            "measurement": "scalability",
            "system_variant": "adaptive",
            "drones": row["drones"],
            "auth_latency_ms_mean": row["hint_auth_latency_ms_mean"],
            "ids_ms_per_window_mean": row["ids_ms_per_window_mean"],
            "trust_policy_ms_per_window_mean": row["trust_policy_ms_per_window_mean"],
            "monitor_ms_per_window_mean": row["monitor_ms_per_window_mean"],
            "runtime_wall_s": row["wall_s"],
            "receptions": row["receptions"],
            "memory_rss_mb": row["rss_mb"],
            "limitation": "Trust/policy cost is combined; no isolated policy-only timer is recorded.",
        }
        for row in scale
    ] + [
        {
            "measurement": "variant_summary",
            "system_variant": row["variant"],
            "drones": "10-scenario aggregate",
            "auth_latency_ms_mean": "",
            "ids_ms_per_window_mean": row["monitor_ids_ms_per_window"],
            "trust_policy_ms_per_window_mean": "",
            "monitor_ms_per_window_mean": row["monitor_ms_per_window"],
            "runtime_wall_s": "",
            "receptions": "",
            "memory_rss_mb": "",
            "limitation": "Variant-level summary from baseline/comparison runs.",
        }
        for row in read_csv(ROOT / "raw/baseline_comparison/runs.csv")[:0]
    ])

    write_csv(OUT / "contribution_matrix.csv", [
        {"component": "D2DAP", "existing_literature": "Existing protocol family", "our_implementation": "Implemented in software simulation", "our_contribution": "Implementation/integration", "experimental_evidence": "Current-head authentication and STRIDE runs", "limitation": "Software cryptography and software PUF"},
        {"component": "ML IDS", "existing_literature": "Existing ML methods and IDS framing", "our_implementation": "Generated-data multiclass IDS", "our_contribution": "Implementation/evaluation", "experimental_evidence": "Current-head metrics and stress split", "limitation": "Simulator-generated data; no real-drone generalization"},
        {"component": "Attribution-aware trust", "existing_literature": "Related reputation/trust concepts", "our_implementation": "Implemented decayed evidence fusion", "our_contribution": "Proposed integration", "experimental_evidence": "Trust validation and attribution ablation", "limitation": "Model assumptions and controlled evidence cases"},
        {"component": "Adaptive policy", "existing_literature": "Adaptive response is established; exact integration varies", "our_implementation": "Graded policy with hysteresis and receiver enforcement", "our_contribution": "System-level integration contribution", "experimental_evidence": "Baseline, ablation, STRIDE, scalability", "limitation": "Simulation-only response and timing"},
    ])

    write_csv(OUT / "research_questions.csv", [
        {"research_question": "RQ1", "experiment": "D2DAP authentication and STRIDE", "metric": "success rate; rejection signals", "result": "All current authentication trials succeeded; attacks were exercised", "interpretation": "Reproducible in the software simulation", "limitation": "Not a formal proof or hardware deployment"},
        {"research_question": "RQ2", "experiment": "Authentication benchmark", "metric": "mean/median/std/P95/P99 latency; bytes", "result": "128-bit hint mean 32.77 ms; 304 bytes", "interpretation": "D2DAP introduces measurable software cost", "limitation": "Host-dependent timing"},
        {"research_question": "RQ3", "experiment": "IDS model and unseen-rate stress", "metric": "macro-F1, binary-F1, FPR/FNR", "result": "XGBoost macro-F1 0.9439; stress macro-F1 0.8288", "interpretation": "Useful within generated simulator data", "limitation": "Real-world generalization unestablished"},
        {"research_question": "RQ4", "experiment": "Trust validation and attribution ablation", "metric": "trust trajectory and policy state", "result": "Verified insider evidence penalizes faster; unverified spoofing is discounted", "interpretation": "Trust adds identity-aware information beyond IDS probability", "limitation": "Controlled evidence sequence, not field data"},
        {"research_question": "RQ5", "experiment": "Baseline/adaptive and ablation comparison", "metric": "mitigation, response, state, collateral", "result": "Adaptive framework mitigates 0.9549 on aggregate with 2200 ms median response", "interpretation": "Supports a measurable system-level response benefit", "limitation": "Variant metrics are simulator-specific"},
        {"research_question": "RQ6", "experiment": "Scalability and variant overhead outputs", "metric": "IDS, trust/policy, monitor and runtime costs", "result": "Costs are recorded for 5, 10, 25, 50, 100 drones", "interpretation": "Adaptive processing introduces measurable overhead", "limitation": "Trust/policy components are combined"},
    ])

    write_csv(OUT / "hypothesis_evaluation.csv", [
        {"hypothesis": "H1", "status": "SUPPORTED", "evidence": "Adaptive comparison and ablation", "qualification": "Within tested simulated scenarios"},
        {"hypothesis": "H2", "status": "PARTIALLY SUPPORTED", "evidence": "Repeated malicious behaviour reaches graded states; timestamps are aggregated", "qualification": "No complete per-event response-time distribution"},
        {"hypothesis": "H3", "status": "SUPPORTED", "evidence": "Authentication, monitor, trust/policy, and runtime timings", "qualification": "Host-dependent software overhead"},
        {"hypothesis": "H4", "status": "SUPPORTED", "evidence": "Current-head IDS metrics and stress split", "qualification": "Only simulator-generated traffic"},
    ])

    write_csv(OUT / "claim_audit.csv", [
        {"claim": "secure authentication", "classification": "SUPPORTED BY EXPERIMENT", "basis": "D2DAP current-head success and rejection tests", "limitation": "Software simulation"},
        {"claim": "adaptive security", "classification": "SIMULATION-ONLY", "basis": "Baseline, ablation, and STRIDE results", "limitation": "No deployment validation"},
        {"claim": "real-time detection", "classification": "SUPPORTED BY EXPERIMENT", "basis": "One-second monitor windows and measured processing", "limitation": "Host and simulator timing"},
        {"claim": "scalability", "classification": "SUPPORTED BY EXPERIMENT", "basis": "5/10/25/50/100 drone runs", "limitation": "Do not extrapolate beyond tested sizes"},
        {"claim": "energy efficiency", "classification": "NOT SUPPORTED", "basis": "No hardware energy measurement", "limitation": "Requires physical instrumentation"},
        {"claim": "physical PUF security", "classification": "NOT SUPPORTED", "basis": "PUF is software model", "limitation": "No physical unclonability evidence"},
        {"claim": "real drone deployment", "classification": "NOT SUPPORTED", "basis": "Software simulation only", "limitation": "No field deployment"},
        {"claim": "ML generalization", "classification": "NOT SUPPORTED", "basis": "Training/evaluation use simulator data", "limitation": "No external real-world validation"},
        {"claim": "STRIDE resistance", "classification": "SUPPORTED BY EXPERIMENT", "basis": "Current-head STRIDE matrix and runs", "limitation": "Attack-model and simulator boundaries"},
        {"claim": "trust-aware mitigation", "classification": "SIMULATION-ONLY", "basis": "Attribution validation and ablation", "limitation": "Controlled model assumptions"},
    ])

    stride_src = ROOT / "tables/stride_table.csv"
    shutil.copy2(stride_src, OUT / "stride_evaluation.csv")
    (OUT / "figures").mkdir(parents=True, exist_ok=True)
    for source in (ROOT / "figures").glob("*.png"):
        shutil.copy2(source, OUT / "figures" / source.name)


if __name__ == "__main__":
    main()
