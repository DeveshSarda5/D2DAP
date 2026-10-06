# Adaptive Trust-Aware Drone Security Framework

**D2DAP authentication + ML-based intrusion detection + continuous trust and adaptive policy.**
This is a software-only research system: a final-year B.Tech major project by **Kapil and Devesh**.

> Everything here is a **software simulation**: drones, the wireless channel, the PUF (a *software PUF model*) and the attacks are simulated.
> The cryptography (ECC, SHA-3, AES) is real.
> No hardware timing, physical-PUF or energy results are claimed. All numbers in `results/` are reproducible from a seed.

## What is ours and what is not

| Category | Items |
|---|---|
| **Existing research (not our contribution)** | D2DAP protocol (Parai et al., IEEE TVT 2026); PUF-based authentication; Shamir threshold sharing; STRIDE; ML-based IDS for IoD (Ogab et al., IEEE Access 2025); LR/DT/RF/XGBoost; Beta-reputation basics |
| **Our implementation** | Drone-swarm simulator; software PUF; full D2DAP implementation (real cryptography); authenticated data plane; traffic and 10-attack simulator; ML pipeline with leakage checks; benchmarking and experiment automation; dashboard; demo |
| **Our proposed contribution** | Continuous **attribution-aware trust** that fuses D2DAP outcomes with ML evidence; a **graded adaptive policy** (NORMAL → MONITOR → RESTRICT → RE-AUTHENTICATE → QUARANTINE) with hysteresis, hard rules, recovery and explanations; **re-authentication as an ambiguity resolver**; and an evaluation of the adaptive layer (baselines A–D, ablation, scalability) |

See [`docs/research-contribution.md`](docs/research-contribution.md) and [`docs/d2dap-implementation-mapping.md`](docs/d2dap-implementation-mapping.md). The mapping lists every deviation from the paper.

## Architecture

```
Drone simulator -> D2DAP MAKA (software PUF, ECC, Shamir) -> authenticated sessions (AES-GCM)
   -> traffic (+ simulated attacks) -> window features -> ML IDS (P(attack), class)
   -> TrustEngine (attribution-aware decayed Beta, + D2DAP auth events)
   -> PolicyEngine -> CONTINUE / MONITOR / RESTRICT / RE-AUTHENTICATE / QUARANTINE
                                         (forced fresh MAKA)  <-------'
```

Details: [`docs/architecture/`](docs/architecture). Trust model: [`docs/architecture/trust-model.md`](docs/architecture/trust-model.md).

## Quick start (Windows / Linux / macOS, Python ≥ 3.10)

```bash
python -m venv .venv
```
```bash
.venv/Scripts/python -m pip install -e ".[dev]"
```
(On Linux/macOS use `.venv/bin/python`.)

| Task | Command |
|---|---|
| All checks (format, lint, mypy --strict, tests) | `python scripts/check_all.py` (add `--fast` to skip slow tests) |
| **Professor demo** (narrated, about 2 min) | `python scripts/run_demo.py` (try `--attack spoofing` or `--attack privilege_escalation`) |
| **Dashboard** (live simulation) | `python scripts/run_dashboard.py`, then open http://127.0.0.1:8000 |
| **All experiments** (several hours) | `python scripts/run_experiments.py` |
| One suite / smoke run | `python scripts/run_experiments.py --suite ids,showcase` or `--quick` |

Experiment outputs go to `results/raw`, `processed`, `tables`, `figures` and `reports`. Every experiment saves its seed, configuration, environment, git commit, raw data and a structured log. Every table and figure has a `.source.json` naming the data it came from.
The compiled tables are in [`results/reports/final_tables.md`](results/reports/final_tables.md), the figure list in [`results/reports/figures_index.md`](results/reports/figures_index.md) and the audit in [`docs/FINAL_PROJECT_AUDIT.md`](docs/FINAL_PROJECT_AUDIT.md).

## Repository layout

```
backend/app/
  simulation/   drones, mobility, channel, network, traffic, traffic log
  security/     crypto suite, Shamir, D2DAP signature, software PUF, d2dap/ (CS, agents, service)
  services/     secure transport, auth coordinator, swarm builder, security monitor, framework, live
  attacks/      10 STRIDE-mapped attacks (external + insider), manager
  ids/          features, dataset generation, validation/leakage checks, models, evaluation, NSL-KDD loader
  trust/        TrustEngine (our contribution)
  policy/       PolicyEngine + enforcement (our contribution)
  benchmarks/   authentication benchmark, statistics, literature values (labelled)
  experiments/  recorder, scenarios, STRIDE, IDS, comparison/ablation, scalability, plots, report
  api/          FastAPI app
backend/tests/  unit / integration / e2e
frontend/       dashboard (HTML/CSS/JS, no build step)
docs/           research understanding, contribution, mapping, architecture, research notes, audit
scripts/        check_all, run_experiments, run_demo, run_dashboard, demo_simulator
```

## Public dataset (optional)

The ML pipeline also supports **NSL-KDD**. The official download (https://www.unb.ca/cic/datasets/nsl.html) requires a registration form, so it is not fetched automatically.
Place `KDDTrain+.txt` and `KDDTest+.txt` in `data/raw/nsl-kdd/` and re-run `--suite ids`.

## Limitations (summary)

Simulation only; the software PUF is not unclonable; the IDS is trained and evaluated on simulated traffic; trust and policy parameters are design choices (sensitivity is reported, not tuned to the test set); the monitor is hosted on the leader and is trusted.
The full list is in [`docs/FINAL_PROJECT_AUDIT.md`](docs/FINAL_PROJECT_AUDIT.md).

## References

1. K. Parai, P. K. Roy, P. Kumar, SK H. Islam, "D2DAP: Provably Secure and Efficient Drone-to-Drone Authentication Protocol Using Threshold Cryptography and PUF", *IEEE Trans. Vehicular Technology*, 2026, doi:10.1109/TVT.2026.3674144.
2. M. Ogab, S. Zaidi, A. Bourouis, C. T. Calafate, "Machine Learning-Based Intrusion Detection Systems for the Internet of Drones: A Systematic Literature Review", *IEEE Access* 13, 2025, doi:10.1109/ACCESS.2025.3575236.
3. A. Jøsang, R. Ismail, "The Beta Reputation System", *Bled eConference*, 2002.
4. A. Shamir, "How to share a secret", *Commun. ACM* 22(11), 1979.
5. M. Tavallaee et al., "A detailed analysis of the KDD CUP 99 data set" (NSL-KDD), *IEEE CISDA*, 2009.
