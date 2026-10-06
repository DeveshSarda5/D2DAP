# Codebase Architecture and Execution Flow

Status: Phase 1 reverse-engineering of the existing implementation.

This document describes what is established by the current source code. It does not
describe a proposed redesign and it does not claim that the simulator is physical
drone hardware.

## 1. Executive architecture

The project is a software-only, deterministic, discrete-time drone-swarm security
simulation. A single Python process hosts the simulator, security services, FastAPI
application, and the static dashboard. The dashboard is not a separate frontend build
project.

```text
Browser: frontend/index.html + frontend/app.js + frontend/styles.css
                |
        HTTP JSON requests; polling every 1 second
                |
FastAPI: backend/app/api/main.py
                |
LiveSimulation: backend/app/services/live.py
                |
SecureSwarm
  SimulationEngine -> DroneNetwork -> WirelessChannel -> Packet queue
        |                    |
        |                    +--> TrafficLog
        |                    +--> protocol handlers / policy ingress filters
        |
  D2DAPSystem + AuthCoordinator + SecureTransport
        |
  SecurityMonitor (1-second windows)
    extract_windows -> trained IDS -> Evidence -> TrustEngine
                                      -> PolicyEngine -> PolicyEnforcer
```

The complete live stack is assembled by `build_variant()` in
`backend/app/experiments/scenario.py`, which calls `build_secure_swarm()` and, for
the IDS/trust/policy variants, `install_framework()` in
`backend/app/services/framework.py`.

## 2. Technology inventory

| Area | Current implementation |
|---|---|
| Languages | Python, JavaScript, HTML, CSS, Markdown, CSV/JSON |
| Frontend | Vanilla browser JavaScript; no React, Next.js, Vue, or frontend build step |
| Backend | FastAPI with Uvicorn |
| Validation/configuration | Pydantic models and dataclasses |
| Numerical/data work | NumPy and pandas |
| ML | scikit-learn pipelines plus XGBoost |
| Cryptography | `cryptography`, `ecdsa`, project crypto wrappers; ECC, SHA-3, AES-CTR/AES-GCM depending on layer |
| Simulation | Project-owned discrete-event/tick simulator; no external drone or network simulator |
| Persistence | No database. Runtime state is in Python objects. CSV, JSON, PNG, and Markdown files are written by experiments/demo scripts |
| Concurrency | One optional background `threading.Thread` for live dashboard simulation; protected by an `RLock` |
| API transport | HTTP JSON; dashboard uses `fetch()` and polling |
| Model artifact | `results/models/ids_operational.joblib` loaded with joblib |
| Tests | pytest; unit, integration, and end-to-end tests under `backend/tests` |

The dependency and quality configuration is in `pyproject.toml`. The package is
installed from the `backend` directory through setuptools package discovery, so the
normal setup is an editable install from the repository root.

## 3. Repository structure

```text
backend/app/
  api/                 FastAPI routes and static-file serving
  attacks/             Attack specifications, external attacks, insider attacks
  benchmarks/          Authentication and literature comparison measurements
  core/                clock, RNG streams, logging, configuration/errors
  experiments/         scenario construction, evaluation, recording, plots, reports
  ids/                 observable features, dataset generation, models, evaluation
  models/              Packet and enum domain models
  policy/              Policy state machine and receiver-side enforcement
  schemas/             Shared schema package
  security/            crypto, PUF, D2DAP, secret sharing, signatures
  services/            swarm wiring, authentication coordinator, transport, monitor, live service
  simulation/          engine, network, channel, mobility, drones, traffic, traffic log
  trust/               decayed Beta trust engine and parameters
backend/tests/
  unit/                focused component tests
  integration/         attacks, API, dataset, data plane, STRIDE, comparisons
  e2e/                 full framework/reproducibility tests
frontend/
  index.html           dashboard markup and controls
  app.js               rendering, event handlers, API polling
  styles.css           dashboard presentation
scripts/
  run_demo.py          narrated end-to-end demonstration
  run_dashboard.py     Uvicorn entry point
  run_experiments.py   experiment-suite entry point
  check_all.py         formatting, lint, mypy, tests
  verify_reproducibility.py reproducibility checks
data/                  raw/processed/generated simulation and optional public data
results/               generated experiment/demo artifacts
docs/                  architecture, research, audit, and result documentation
```

There is no runtime `.env` contract referenced by the application code. The IDS model
path can be overridden with the `ADS_IDS_MODEL` environment variable; otherwise the
default is `results/models/ids_operational.joblib`.

## 4. Frontend architecture

`frontend/index.html` contains the complete page. It defines:

- top controls: drones, seed, system variant, speed, Start, Stop;
- metric tiles;
- SVG topology area;
- drone table;
- trust and attack-probability charts rendered by `app.js`;
- attack form;
- recent event list.

`frontend/app.js` is a single vanilla JavaScript module-like script. It has no client
router, Redux/store, component framework, or WebSocket connection. Important functions
are:

| Function | Responsibility |
|---|---|
| `api(path, opts)` | Calls a JSON HTTP endpoint using `fetch()` and raises on non-2xx responses |
| `renderTiles(m)` | Converts `/api/metrics` values into the eight metric tiles |
| `renderTopology(st)` | Converts state positions and edges into SVG lines/circles |
| `renderTable(st)` | Converts drone summaries into the table and target selector |
| `renderCharts(tr)` | Draws trust and IDS-probability SVG line charts |
| `renderEvents(evts)` | Prepends event records to the event list and tracks event IDs |
| `refresh()` | Fetches state, metrics, trust history, and new events concurrently |
| `init()` | Loads attack kinds, installs Start/Stop/Launch handlers, starts polling |

The browser polls once per second through `setInterval(refresh, 1000)`. Each refresh
calls `/api/state`, `/api/metrics`, `/api/trust`, and `/api/events?since=<lastEventId>`.
This is ordinary HTTP polling, not streaming.

### Frontend-to-backend UI map

| UI | Browser state/source | Backend endpoint | Effect |
|---|---|---|---|
| Drones, Seed, System, Speed | Current DOM input values read only when Start is clicked | `POST /api/simulation/start` | Builds a new live simulation with those values |
| Start | `btn-start` handler | `main.start()` -> `LIVE.start()` | Stops old run, builds a new swarm, optionally starts a background thread |
| Stop | `btn-stop` handler | `POST /api/simulation/stop` -> `LIVE.stop()` | Sets the run flag false and joins the worker thread for up to 5 seconds |
| Metric tiles | `/api/metrics` response | `LIVE.metrics()` | Displays counters and averages from live objects |
| Topology | `/api/state` `drones` and `edges` | `LIVE.state()` -> `network.topology()` | Draws current active nodes and in-range links |
| Drone table | `/api/state` `drones` | `Drone.summary()` plus CRP/session fields | Displays role, auth, trust, policy state, battery, sessions, CRPs |
| Trust chart | `/api/trust` | `LIVE.trust_history()` | Displays recent `TrustUpdate.new` values and policy threshold bands |
| IDS chart | `/api/trust` | `LIVE.trust_history()` | Displays `Evidence.attack_prob` values per trust update/window |
| Attack selector | `GET /api/attacks/kinds` | `main.attack_kinds()` | Populates actual registered traffic attacks |
| Attack target | Current drone table/state | `/api/state` | Populated with registered non-radio drones |
| Launch | `btn-attack` handler | `POST /api/attacks` -> `LIVE.launch_attack()` | Adds an `Attack` to the running swarm's `AttackManager` |
| Events | `/api/events?since=...` | `LIVE._event()` and `LIVE._collect()` | Displays system, attack, auth, IDS, and policy events |

## 5. FastAPI routes and data flow

Routes are defined in `backend/app/api/main.py`.

| Method/path | Request | Handler and source | Response/purpose |
|---|---|---|---|
| `GET /api/health` | none | `health()` | `{"status":"ok","version":...}` |
| `POST /api/simulation/start` | JSON matching `LiveConfig`: `num_drones`, `seed`, `variant`, `speed` | `start()` -> `LIVE.start()` | Current live status |
| `POST /api/simulation/stop` | none | `stop()` -> `LIVE.stop()` | Current live status with `running=false` |
| `POST /api/simulation/step` | query `ticks` | `step()` -> `LIVE.step()` | Current status; deterministic manual stepping |
| `GET /api/state` | none | `state()` -> `LIVE.state()` | status, drones, topology edges, active attack evidence |
| `GET /api/events?since=N` | query `since` | `events()` -> `LIVE.events()` | event records newer than ID N |
| `GET /api/trust` | none | `trust()` -> `LIVE.trust_history()` | recent per-drone trust/probability series and bands |
| `GET /api/metrics` | none | `metrics()` -> `LIVE.metrics()` | counters, states, processing average, report/revocation counts |
| `GET /api/attacks/kinds` | none | `attack_kinds()` | registered traffic attack names, STRIDE tags, insider flag |
| `POST /api/attacks` | `kind`, `target`, `duration_s`, `rate_pps` | `launch()` -> `LIVE.launch_attack()` | generated attack ID |
| `GET /` | none | `index()` | `frontend/index.html` |
| `/static/*` | none | mounted StaticFiles directory | CSS and JavaScript |

## 6. Start execution flow

The exact live path is:

```text
Click Start
  -> frontend/app.js anonymous Start handler
  -> api("/api/simulation/start", POST, JSON body)
  -> backend/app/api/main.py:start(config)
  -> backend/app/services/live.py:LiveSimulation.start()
  -> stop previous run
  -> ScenarioConfig + Variant
  -> scenario.build_variant()
  -> services.swarm.build_secure_swarm()
  -> SimulationEngine + DroneNetwork + channel + traffic
  -> D2DAPSystem + AuthCoordinator + SecureTransport
  -> enroll every drone with the Control Server
  -> install SecurityMonitor for IDS/trust/policy variants
  -> start daemon thread _loop() if background=True
  -> _loop() calls step(1), sleeps according to tick_ms/speed
  -> frontend refresh() polls snapshots once per second
```

`LiveSimulation.start()` uses a 1,000,000,000 ms simulation duration, 64 initial
CRPs, and re-provisioning below 8 CRPs for the long-running dashboard. The selected
variant is validated by `LiveConfig`. If the requested IDS model is missing,
`ModelUnavailableError` causes the live service to fall back to `no_ml` and expose a
notice in the dashboard.

The visible Speed value is passed as `simulated seconds per wall second`; it changes
the worker sleep budget. It does not change the simulation's virtual tick size or
packet-generation formulas.

## 7. Stop execution flow

The exact Stop path is:

```text
Click Stop
  -> frontend/app.js btn-stop handler
  -> POST /api/simulation/stop
  -> main.stop()
  -> LIVE.stop()
  -> _running = False
  -> join worker thread, timeout 5 seconds
  -> _thread = None
  -> frontend refreshes status and snapshots
```

Stop does not destroy the `LiveSimulation` singleton, clear the swarm, erase event
history, or close a stream. It stops the background loop. The next Start calls
`stop()` again and then replaces the stored swarm, monitor, attack manager, and event
deque contents for a fresh run. Manual `/api/simulation/step` can still advance the
stored swarm after Stop because `LIVE.step()` does not require `_running` to be true.

## 8. Simulation architecture

`SimulationEngine.step()` advances one virtual tick, then:

1. advances `SimulationClock`;
2. moves active drones through the configured mobility model;
3. generates packets from each active drone's traffic sources;
4. sends packets through the optional secure-transport/auth hook;
5. schedules/delivers packets through `DroneNetwork` and `WirelessChannel`;
6. updates the battery model;
7. invokes tick hooks such as `SecurityMonitor._tick()` and `AttackManager._tick()`.

`build_secure_swarm()` creates the engine, D2DAP system, transport, coordinator,
traffic log, then creates and joins the swarm. `SimulationEngine.create_swarm()` makes
leader(s), relays, and workers; `add_drone()` assigns a seeded random position and
normal traffic sources.

Normal traffic is represented by Python `Packet` objects, not OS sockets or actual
radio frames. The default profile includes periodic telemetry, heartbeat broadcasts,
optional on/off video bursts, and leader commands. The channel uses Euclidean range,
distance-dependent loss, base latency, transmission time, and optional jitter.

`DroneNetwork.topology()` creates an undirected edge for every pair of active nodes
whose current Euclidean distance is within `comm_range_m`. The dashboard receives
these edges from `LIVE.state()` and scales the current positions into SVG coordinates.
Therefore the graph is a real topology of the simulator's current nodes and channel
range model, but it is not a real RF or multi-hop network. Packets addressed out of
range are dropped; the project explicitly leaves multi-hop routing out of scope.

## 9. Packet and delivery flow

`PacketFactory.make()` creates a packet with a unique packet ID, source sequence
number, claimed `src`, physical `true_src`, destination, protocol, size, and optional
payload/attack metadata. `Packet` records receiver-side verdicts such as
`integrity_ok`, `auth_ok`, and `dropped_reason`.

`DroneNetwork.send()` increments sent counters, records a transmission, expands
broadcasts into receiver copies, applies range/loss checks, and schedules successful
copies in a time-ordered queue. `deliver_due()` applies receiver ingress filters,
protocol handlers, receiver records, and packet observers.

The dashboard's `Packets delivered` tile is not a packet count. In
`frontend/app.js:renderTiles()`, it is:

```text
packets_delivered / (packets_delivered + packets_dropped) * 100
```

The counts come from `DroneNetwork.counters`; they refer to simulated packet delivery
attempts, including security/control traffic, not real network packets.

## 10. D2DAP and authenticated transport

The D2DAP implementation is in `backend/app/security/d2dap`. The Control Server runs
setup and registration; the server is not called during the normal D2D MAKA exchange.

Registration (`ControlServer.register()`):

1. generate unique 128-bit challenges;
2. the agent evaluates its bound software PUF and computes `a = H(PUF(C) || ID)`;
3. the agent creates an ECC private scalar `x` and public point `Y`;
4. the Control Server evaluates the degree-one Shamir polynomial to issue shares `b`;
5. it computes verifier `V = H(A || ID)`, publishes `Y`, and installs credentials.

The agent stores the private scalar, challenges, shares, and verifier. It regenerates
`a` from the PUF when needed; `a` and raw PUF responses are not stored as credentials.

Packet-level authentication is managed by `AuthCoordinator` and starts on demand when
`SecureTransport` sees a unicast data packet without a session. The coordinator holds
the original packet, sends an `AUTH_REQUEST` containing D2DAP M1, and installs packet
handlers for `AUTH_REQUEST`, `AUTH_RESPONSE`, and revocation broadcasts.

The implemented exchange is:

```text
D_i / AuthCoordinator                 D_j / AuthCoordinator
       |-- AUTH_REQUEST (M1: encrypted share body + signatures) -->|
       |                                                           |
       |                                      decrypt, freshness,
       |                                      signature, RL, Shamir,
       |                                      verifier checks
       |<-- AUTH_RESPONSE (M2: encrypted body + signatures) -------|
       |                                                           |
       | decrypt, freshness, RL, Shamir and signature checks       |
       |                                                           |
       |========= both derive H(a_i || a_j || T_i || T_j) ========|
       |              install session and release held data        |
```

`DroneSecurityAgent.initiate()`, `respond()`, and `complete()` implement the three
local phases. Freshness uses `delta_t_ms` (default 2 seconds). `peer_resolution` can
use a link-layer hint or trial decryption; the default D2DAP config is `trial`, while
the packet coordinator supplies the claimed source as a hint in its handler. The
default `replay_cache` is false, matching the documented paper-faithful mode.

The project uses a software PUF (`XORArbiterPUF` by default), not physical hardware.
`BoundPUF` prevents a different logical device from querying it. The PUF is seeded
software state and therefore cannot support a real-world claim of physical
unclonability. D2DAP cryptographic operations are real library operations, but timing
and radio behaviour remain simulated/host-dependent.

`SecureTransport` seals application data with established session keys and the
coordinator/transport annotate packets with authentication and integrity outcomes.
The project has both direct `D2DAPSystem.authenticate()` measurements for protocol
benchmarking and packet-level MAKA used by the running swarm; these are related paths,
but they are not the same call path.

## 11. Attacks

`AttackManager` registers these actual attack types:

| Attack | Implementation | Insider? | STRIDE |
|---|---|---:|---|
| `spoofing` | `external.SpoofingAttack` | No | S |
| `replay` | `external.ReplayAttack` | No | S, D |
| `tampering` | `external.TamperingAttack` | No | T |
| `dos_auth_flood` | `external.DosAuthFloodAttack` | No | D |
| `impersonation` | `external.ImpersonationAttack` | No | S, E |
| `unauthorized_access` | `external.UnauthorizedAccessAttack` | No | E |
| `eavesdropping` | `external.EavesdroppingAttack` | No; excluded from traffic selector | I |
| `flooding` | `insider.FloodingAttack` | Yes | D |
| `privilege_escalation` | `insider.PrivilegeEscalationAttack` | Yes | E |
| `abnormal` | `insider.AbnormalTrafficAttack` | Yes | D |

Traffic attacks attach an attack source or transform real `Packet` objects. External
attacks create an `X-...` radio node that shadows a target; insider attacks use a
legitimate registered drone. The attack scheduler is a tick hook, so launching an
attack adds it to the running engine and its `tick()` method drives start, packet
generation/transformation, and stop at virtual times.

## 12. IDS architecture

The IDS data path is implemented by `SecurityMonitor`:

```text
TrafficLog records
  -> extract_windows(..., with_labels=False)
  -> one row per claimed src per 1000 ms window
  -> trained TrainedModel.predict_proba()
  -> p_attack = 1 - P(benign)
  -> p_insider = sum probabilities of insider classes
  -> class = highest-probability class
  -> alert if p_attack >= ids_threshold (default 0.5)
```

The observable feature set is defined in `backend/app/ids/features.py` and includes
counts, byte/size statistics, destination diversity, inter-arrival statistics,
protocol fractions, authentication outcomes, integrity/replay/no-session verdicts,
sequence anomalies, command counts, leader role, and verified traffic counts.

Ground truth fields (`true_src`, `label`, `attack_id`) are deliberately not used by
feature extraction. The attack label is used only when generating/training/evaluating
datasets, not in live inference. The model training path in `backend/app/ids/models.py`
uses a preprocessing pipeline with non-negative `log1p`, standardisation, balanced
class handling, and grouped cross-validation on training data. Four models are
available; the operational artifact is loaded from the joblib file.

An IDS window is a one-second interval grouped by claimed source address. In live
operation, `SecurityMonitor._tick()` processes a window after its end plus grace time.
The live chart's displayed probability is the `Evidence.attack_prob` value from the
monitor's trust log, not a separately computed frontend probability.

## 13. Trust architecture

`TrustEngine` is an attribution-aware decayed Beta reputation model. A registered
drone starts from prior alpha 4.0 and beta 0.5; an unknown source starts from alpha 1.0
and beta 1.0. Trust is `alpha / (alpha + beta)`.

For each evidence window, alpha and beta are first multiplied by `decay=0.85` per
elapsed window. Positive and negative evidence are then accumulated. Established
components include:

- normal ML evidence: `w_normal * (1 - p_attack)`;
- ML attack evidence: negative `w_ml_attack * p_attack`, split into insider/external
  probability and reduced for traffic not cryptographically attributable to the identity;
- successful MAKA: `w_auth_success * min(successes, 3)`;
- failed MAKA: negative saturating `w_auth_failure * (1 - exp(-n/k))`;
- integrity/replay/unauthenticated violations: negative `w_violation` with saturation;
- non-leader privileged commands: negative violation evidence tied to verified traffic;
- transmission-rate anomaly: corroborating negative evidence;
- successful forced re-authentication: positive `w_reauth_success`.

Default weights and switches are in `backend/app/trust/config.py`; the exact update is
implemented in `TrustEngine.update()` in `backend/app/trust/engine.py`. Repeat-offender
multiplier state is based on bad-window history, capped at 3.0 by default. These are
design parameters studied by the experiments, not learned or proven optimal values.

## 14. Policy architecture

`PolicyEngine.evaluate()` maps each trust update to a state and records a decision only
when the state changes. Default graded thresholds are:

| State | Trust band / trigger | Entry actions |
|---|---|---|
| NORMAL | `>= 0.80` | lift restrictions |
| MONITOR | `>= 0.60` and below NORMAL | increase monitoring |
| RESTRICT | `>= 0.40` and below MONITOR | rate limit, block privileged commands |
| RE-AUTHENTICATE | `>= 0.20` and below RESTRICT | rate limit, block commands, revoke sessions, force MAKA |
| QUARANTINE | `< 0.20`, failed forced authentication, or repeat-offender rule | revoke sessions, drop traffic, block new sessions, broadcast notice |

Hysteresis is 0.05 for relaxation. Quarantine exit additionally requires the minimum
quarantine time (20 seconds by default), successful re-authentication, and trust above
the restrict band plus hysteresis; the next state is RESTRICT/probation. The policy
engine is a state machine, not simply a one-shot threshold comparison.

`PolicyEnforcer` installs a receiver-side network ingress filter. This matters because
a malicious sender will not cooperate with a local sender-side restriction. RESTRICT
rate-limits data/auth traffic and blocks commands; RE-AUTHENTICATE revokes sessions;
QUARANTINE drops traffic except probationary authentication requests. Policy-dropped
packets are inspected where possible so the monitor retains attribution evidence.

## 15. Monitor and event flow

`SecurityMonitor.install()` installs the policy filter, registers an authentication
listener, and adds `_tick()` as an engine tick hook. `_tick()` collects new traffic
records, processes complete one-second windows, computes IDS output, builds `Evidence`,
updates trust, evaluates policy, applies enforcement, and emits trust-report packets.

The live service converts internal events into dashboard events:

- `LIVE._event("system", ...)` when a run starts;
- `LIVE._event("attack", ...)` when an attack is injected;
- `LIVE._on_auth()` for visible D2DAP failures and forced re-authentication;
- `LIVE._collect()` for new IDS alerts and policy decisions.

Events are dictionaries with a monotonically increasing `id`, simulation `t_ms`,
`kind`, `message`, and optional fields such as `drone`, `state`, `p`, and
`explanation`. They are stored in an in-memory bounded deque of 300 records. The browser
uses the last event ID so polling requests only newer records.

## 16. Runtime sequence: normal operation

```text
Start -> build swarm -> register drones -> install handlers/hooks
  -> engine tick advances virtual time
  -> mobility changes positions and topology
  -> normal sources create Packet objects
  -> coordinator/transport authenticates on first protected unicast
  -> Network schedules and delivers packets
  -> TrafficLog records final fate
  -> SecurityMonitor groups records into one-second source windows
  -> IDS scores benign/attack probability
  -> TrustEngine updates registered-source trust
  -> PolicyEngine normally keeps NORMAL
  -> LIVE snapshots are polled by browser
```

## 17. Runtime sequence: attack injection

For a request such as `spoofing`, target `D2`, duration 30, rate 20:

```text
frontend/app.js btn-attack handler
  -> POST /api/attacks {kind, target, duration_s:30, rate_pps:20}
  -> api.main:launch()
  -> live.LiveSimulation.launch_attack()
  -> AttackManager.launch(AttackSpec(start=now+1, duration=30000, rate=20))
  -> SpoofingAttack is added to engine tick hooks
  -> external attacker node/source emits forged real Packet objects
  -> Network/channel/transport/auth handlers process them
  -> TrafficLog stores observable verdicts and evaluation-only ground truth
  -> SecurityMonitor processes the affected one-second window
  -> IDS produces p_attack and class
  -> TrustEngine fuses IDS/auth/verification/attribution evidence
  -> PolicyEngine may change state
  -> PolicyEnforcer applies receiver-side restrictions
  -> LIVE._collect() turns alerts/decisions into events
  -> next browser poll redraws tiles, table, charts, and event log
```

The event saying an attack was injected explicitly labels it as ground truth for the
demo. Ground truth is not fed into live IDS feature extraction.

## 18. Configuration and variants

The dashboard exposes these variants through `LiveConfig`:

| UI value | Framework mode |
|---|---|
| `adaptive` | full IDS + attribution-aware trust + graded policy |
| `d2dap_ids_trust` | IDS + trust with binary policy |
| `d2dap_ids` | IDS alert/block for one window |
| `no_ml` | adaptive policy without ML; trust uses non-ML evidence |
| `d2dap` | D2DAP and authenticated data plane only; no monitor |

`framework.py:VARIANT_SPECS` is the authoritative mapping. The baseline variant used
by experiments is also available to scenario code but is not a selectable dashboard
value.

## 19. Research boundary established by the code

The implementation supports these defensible statements:

- D2DAP-like mutual authentication and session establishment are implemented with real
  cryptographic primitives in a software simulation.
- The simulator combines packet-level authentication, observable traffic features,
  multiclass IDS inference, attribution-aware trust, and receiver-side adaptive policy.
- The adaptive layer is the project's proposed contribution and is evaluated through
  controlled simulation experiments.
- Results are reproducible for seeded simulation state; host wall-clock measurements
  are machine-dependent.

The current code does not establish claims of physical PUF unclonability, real RF
security, real drone deployment, hardware energy efficiency, Raspberry Pi performance,
formal proof reproduction, or generalisation to real IoD traffic. Multi-hop routing,
physical capture, side channels, leader compromise, and real network sockets are not
implemented by the current runtime.

## 20. Recommended source-reading order

1. `pyproject.toml` and `README.md`
2. `backend/app/models/enums.py` and `backend/app/models/packet.py`
3. `backend/app/simulation/config.py`, `drone.py`, `channel.py`, `network.py`
4. `backend/app/simulation/traffic.py` and `simulation/engine.py`
5. `backend/app/services/swarm.py`
6. `backend/app/security/puf.py` and `security/d2dap/control_server.py`
7. `backend/app/security/d2dap/agent.py` and `d2dap/service.py`
8. `backend/app/services/secure_transport.py` and `auth_coordinator.py`
9. `backend/app/ids/features.py` and `ids/models.py`
10. `backend/app/trust/config.py` and `trust/engine.py`
11. `backend/app/policy/engine.py` and `policy/enforcement.py`
12. `backend/app/services/monitor.py` and `services/framework.py`
13. `backend/app/attacks/base.py`, `attacks/manager.py`, `attacks/external.py`, `attacks/insider.py`
14. `backend/app/services/live.py` and `backend/app/api/main.py`
15. `frontend/index.html`, `frontend/app.js`, and `frontend/styles.css`
16. `scripts/run_demo.py`, `scripts/run_dashboard.py`, and the integration tests

This order follows the actual dependency direction: domain objects -> simulator ->
security -> detection -> trust/policy -> API -> browser.
