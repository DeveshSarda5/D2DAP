# Research contribution results

Date: 2026-10-06  
Current HEAD: `64b9b7f7768467f0a0fa8476104ec4dde74b9e32`

## Executive conclusion

Within the tested software simulation, the full adaptive framework demonstrates a
measurable system-level benefit over authentication-only and selected reduced
configurations: the current comparison reports 100% aggregate detection and 95.49%
mean mitigation for the adaptive variant over 30 runs, with a median response of
2200 ms. The result is supportive evidence for the proposed integration, not proof of
real-world security.

The benefit has trade-offs. The adaptive variant records monitor, trust/policy,
authentication, communication, and response-processing overhead. The current
scalability table measures these costs for 5, 10, 25, 50, and 100 drones. Trust and
policy are reported together because the current instrumentation does not isolate
their individual timings.

## Supported system variants

| Variant | Active components | Disabled components | Executable? |
|---|---|---|---|
| A: `d2dap` | D2DAP authentication, secure transport | IDS, trust, adaptive policy | Yes |
| B: `d2dap_ids` | D2DAP, secure transport, ML IDS | Trust, adaptive policy | Yes |
| C: `d2dap_ids_trust` | D2DAP, secure transport, ML IDS, trust | Graded adaptive policy | Yes |
| D: `adaptive` | D2DAP, secure transport, ML IDS, trust, policy/enforcement | None | Yes |

The comparison is executable through the repository's scenario variants. Metrics are
not equally available for every layer: raw runs expose detection, mitigation, response,
monitor, authentication, and final-state fields, but not every individual trust/policy
transition timestamp.

## Main evidence

- IDS: current XGBoost accuracy `0.9960`, macro-F1 `0.9439`, binary-F1 `0.9856`,
  FPR `0.000803`, and FNR `0.01813`. The unseen-rate stress macro-F1 is `0.8288`.
- Authentication: 128-bit hint mean `32.77 ms`, median `31.98 ms`, standard deviation
  `4.58 ms`, P95 `40.12 ms`, P99 `46.96 ms`, and 304 bytes per exchange; success was
  `1.0` in the measured trials.
- Adaptive comparison: detection `1.0`, layer detection `0.9259`, mitigation `0.9549`,
  median response `2200 ms`, and 30 runs.
- Attribution validation: verified insider evidence drove trust from `0.889` to
  `0.122` over ten controlled windows, while equivalent unverified spoofing evidence
  drove it from `0.889` to `0.657`. This demonstrates that the current trust model
  distinguishes the cases under controlled inputs.
- Reproducibility: the targeted trust/policy validation produced identical SHA-256
  outputs in three executions. Experiment manifests record seed, configuration,
  package versions, host, and commit.

## Adaptive lifecycle limitation

The implementation and dashboard visibly expose IDS alerts, trust updates, policy
decisions, enforcement, and recovery-related state. However, the current experiment
CSV schema does not persist a complete per-run event trace containing T0 through T7.
Therefore this audit does not invent IDS-to-trust, trust-to-policy, enforcement, or
recovery latencies. The available detection/response aggregates are reported in
`research_contribution/security_comparison.csv`; the controlled trust trajectory is in
`research_contribution/trust_response.csv`.

## Hypotheses

- H1 — **SUPPORTED within simulation**: adaptive comparison and ablation show a
  measurable response/mitigation difference versus reduced systems.
- H2 — **PARTIALLY SUPPORTED**: repeated malicious evidence reaches progressively more
  severe trust/policy states, but a complete event-level response-time distribution is
  not stored.
- H3 — **SUPPORTED**: authentication, IDS, trust/policy, monitor, and runtime costs
  are measurable; the overhead is host-dependent.
- H4 — **SUPPORTED within simulator data**: the IDS has strong held-out metrics and a
  weaker but still measurable unseen-rate stress result.

## What is genuinely contributed

The defensible contribution is an implementation and proposed integration of
attribution-aware decayed trust, graded policy with hysteresis/forced
re-authentication, and receiver-side enforcement around D2DAP and an ML IDS in a
reproducible drone-security simulator. D2DAP, PUF concepts, generic ML models, STRIDE,
and Beta-style reputation are not claimed as newly invented here.

## Claim audit

The detailed claim classifications are in `research_contribution/claim_audit.csv`.
In summary:

- Supported by experiment: software authentication behaviour, simulated IDS metrics,
  tested-size scalability, and STRIDE scenario outcomes.
- Simulation-only: adaptive mitigation and trust-aware response.
- Not supported: energy efficiency, physical PUF security, real drone deployment, and
  real-world ML generalization.

## Professor-ready answer

“Our experiments demonstrate in a controlled software simulation that combining D2DAP,
an ML IDS, attribution-aware trust, and graded receiver-side policy can improve the
measured response to simulated attacks compared with reduced configurations. The
adaptive layer introduces measurable processing and communication overhead, and its
benefits depend on simulator assumptions, generated data, and the tested attack set.
We therefore claim a reproducible system-level integration and experimental result,
not physical PUF security, real RF security, energy efficiency, formal proof, or
real-world IDS generalization.”

## Output index

The complete Phase 5 outputs are under
`results/current_head/research_contribution/`:

- `security_comparison.csv`
- `ablation_results.csv`
- `trust_response.csv`
- `adaptive_overhead.csv`
- `contribution_matrix.csv`
- `research_questions.csv`
- `hypothesis_evaluation.csv`
- `claim_audit.csv`
- `stride_evaluation.csv`
- `figures/` with figures copied from current-head experiment data

The source experiment tables remain under `results/current_head/tables/` and the raw
run data remain under `results/current_head/raw/`.
