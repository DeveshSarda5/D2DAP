# Authentication Benchmark (Phase 5)

Code: `backend/app/benchmarks/auth_benchmark.py`. Artefacts: `results/raw/authentication/`, `results/tables/authentication_*`, `results/figures/authentication_*`.
Regenerate with `python scripts/run_experiments.py --suite auth` (Phase 18).

**Result type:** Our Experimental Result. These are software timings on the development machine recorded in the manifest (Python 3.10, pure-Python `ecdsa` point arithmetic).
They are **not** hardware or Raspberry Pi results. The latency is compute time only (network delay 0); network delay is added in the simulation phases.

## Methodology

- 200 timed MAKA runs per configuration (after 10 warm-up runs), between random drone pairs of a 10-drone network. 30 more runs are traced with `tracemalloc` for heap peak.
- Statistics: mean, median, std, P95, P99 and the 95 % CI of the mean.
- CPU time is averaged over the batch, because Windows process timers have about 15.6 ms resolution, which is too coarse for single runs.
- Per-operation micro-benchmarks: 300 repetitions after a warm-up.
- **Host interruptions:** samples above 50× the median are counted and reported (`host_interruptions` column). They are kept in the raw data.
  In one earlier run a single 256-bit point-multiplication sample took 542 s because the OS suspended. That run was superseded by a clean full re-run.
  Derived figures use medians, which are robust to such interruptions.

## Key findings

1. **Correctness:** 100 % success in every configuration (noise-free PUF).
2. **Latency grows with security level.** P-256 is about 30 ms per mutual authentication, P-384 about 64 ms and P-521 about 128 ms (both sides together).
   Run-to-run variation of the mean on this laptop is ±20 % (one earlier full run gave 24 ms at 128-bit). Quote the run in `results/` together with its manifest.
3. **Point multiplication dominates** (about 95 % of compute time). This is consistent with the paper's cost model.
4. **Peer resolution matters.** Trial decryption, which preserves the paper's anonymity claim, raised the 128-bit latency by about 50 % at n = 10. It grows linearly with n (Phase 17).
5. **Communication cost:**

   | | 128-bit | 192-bit | 256-bit |
   |---|---|---|---|
   | Measured bytes on the wire (ours) | 2432 bits | 3456 bits | 4576 bits |
   | Theoretical, our encoding | 2432 | 3456 | 4576 |
   | **Literature** (paper Table VII) | 1024 | 1536 | 2008 |

   The paper counts parameter lengths with unstated assumptions. Ours are real serialized messages: IV 16 B + `a` + `b` + `T` 8 B + σ1 + σ2.
   We could not reconstruct the paper's 1024 bits from the listed message contents.
   The paper's 256-bit value (2008) does not follow its own ×1.5/×2 progression.

6. **Operation counts vs the paper.** Instrumentation counts 5 point multiplications per drone per MAKA.
   The paper's own Table IX total divided by its Table VIII `T_PM` implies about 4.5–4.6 point multiplications.
   So the paper's accounting is probably one multiplication lower (for example, by merging verification's `h·(βP+γY)`).
   Our op counts multiplied by the paper's per-op cycle costs give an *estimate* about 22 % above the paper's Table IX (`authentication_cycles_estimate` table).
   This is an **Estimated Result**, not a measurement.
7. **PUF noise breaks D2DAP.** With software-PUF noise σ = 0.02, success drops to 50 % (one vote) or 80 % (15-vote majority). At σ ≥ 0.25 it is 0 %.
   The failure is always `secret_mismatch`. D2DAP specifies no fuzzy extractor or helper data, so a real (noisy) PUF would need one.
   This is a deployment gap in the paper.

## Not measured (and not claimed)

Energy, Raspberry Pi CPU cycles and hardware PUF latency.
