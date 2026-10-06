# Software PUF (Phase 3): THIS IS A SOFTWARE PUF SIMULATION

No physical PUF hardware is used anywhere in this project. `backend/app/security/puf.py`
provides software *models* behind a hardware-agnostic interface:

```python
class PUF(Protocol):
    response_bits: int
    def evaluate(self, challenge: bytes) -> bytes: ...
```

A physical PUF driver could replace the model by implementing this interface. `BoundPUF`
attaches a PUF to one device (`owner_id`) and refuses evaluation by any other caller.
This models the physical access restriction in the D2DAP threat model.

## Models

| Model | What it models | Basis |
|---|---|---|
| `XORArbiterPUF` (default) | k-XOR Arbiter PUF, additive delay model: `bit = Π_k sign(w_k · Φ(c))`, `Φ_j = Π_{l≥j}(1−2c_l)`. Per-device weights ~ N(0,1) model manufacturing variation. Optional Gaussian evaluation noise and majority voting. k = 4, 128 stages, 128-bit responses from 128 SHAKE-256-derived sub-challenges. | Standard PUF literature. It is the same model family as `pypuf`'s XOR Arbiter PUF, which the D2DAP authors used. |
| `IdealPUF` | The idealised assumptions of D2DAP's proof: unique, unpredictable, noise-free | HMAC-SHA3-256 under a per-device 256-bit secret |

## Tests (`backend/tests/unit/test_puf.py`)

The four PUF cases from D2DAP Sec. III-B are tested for both models:

| Case | Condition | Expected | Status |
|---|---|---|---|
| 1 | different device, different challenge | different response | pass |
| 2 | same device, different challenge | different response | pass |
| 3 | different device, same challenge | different response | pass |
| 4 | same device, same challenge | **same** response | pass |
| access | non-owner evaluates a `BoundPUF` | `PUFAccessError` | pass |
| clone | replica with different "manufacturing" weights | response Hamming distance > 0.25 | pass |

## Measured quality (Our Experimental Result: software model, seed 42)

Source: `results/raw/puf_quality/puf_quality.csv`, regenerated with `python scripts/run_experiments.py --suite puf`.
16 devices, 40 challenges, 5 re-evaluations.

- Uniqueness ≈ 0.50 and uniformity ≈ 0.50 (ideal 0.5) for all settings.
- Reliability is 1.000 noise-free. It is 0.962 at σ = 0.25 and 0.861 at σ = 1.0 with a single evaluation.
  Five-vote majority voting raises these to 0.979 and 0.918.
- The ideal PUF is perfectly reliable by construction.
- Evaluation time is about 0.35 ms (XOR-Arbiter, numpy) and about 9 µs (ideal) per 128-bit response on the development machine.
  **These are software timings and say nothing about hardware PUF latency.**

## Implication for D2DAP

D2DAP hashes the raw response (`a_ik = H(R_ik ‖ ID_i)`) and specifies **no error correction or fuzzy extractor**.
A single flipped response bit therefore changes `a_ik`, which breaks secret reconstruction (`H(A‖ID) ≠ V`).
With 128-bit responses, the probability that *all* bits are stable is about `reliability^128`.
That is essentially 0 even at reliability 0.96. So D2DAP as specified needs a noise-free PUF, which is the paper's "robustness" assumption.
Our default configuration uses noise σ = 0 to stay faithful. The effect of noise on authentication success is measured in Phase 5.

## Limitations

1. **Not unclonable.** A software PUF's secret (seed or weights) is ordinary memory. Physical unclonability cannot be reproduced in software.
   In the simulation, unclonability is enforced by the model boundary: the attacker's device draws different weights.
2. **Modelling attacks are not evaluated.** XOR Arbiter PUFs are known to be learnable from CRPs by ML.
3. **No environmental effects** (temperature or voltage drift, ageing) beyond i.i.d. Gaussian noise.
4. **Timings are software timings** on the development machine.
