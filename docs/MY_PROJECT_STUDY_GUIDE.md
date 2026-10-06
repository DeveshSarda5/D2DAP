# My Project Study Guide

This guide teaches the implementation currently in the repository. It is a viva and
demonstration guide, not a redesign. Statements about behaviour are tied to source
files and functions; illustrative arithmetic is labelled as such.

## 1. The project in one minute

The project simulates a swarm of drones. Each drone can register with a Control Server
and use D2DAP to authenticate with another drone. After authentication, unicast data is
protected by an AES-GCM session data plane.

The simulator generates normal telemetry, heartbeat, video, and command traffic.
Attack classes inject or alter simulated packets. A one-second feature extractor gives
an ML intrusion detector only receiver-observable information. Its evidence is combined
with authentication results, packet-verification results, and identity attribution in a
decayed Beta trust engine. An adaptive policy maps trust to NORMAL, MONITOR, RESTRICT,
RE-AUTHENTICATE, or QUARANTINE. Enforcement happens at receivers because a malicious
sender cannot be trusted to enforce its own restriction. The browser dashboard polls the
live Python service once per second.

The project contribution is the integrated attribution-aware trust and graded adaptive
response layer. D2DAP and the basic Beta-reputation idea come from prior work; this
project implements and evaluates the integration and response design.

## 2. The pipeline in simple language

```text
Drone simulation
  -> D2DAP authentication
  -> Secure communication
  -> Normal traffic and attacks
  -> ML IDS
  -> Trust update
  -> Policy decision
  -> Receiver-side response
  -> Dashboard snapshot
```

| Arrow | Enters | Happens | Comes out | Implementation |
|---|---|---|---|---|
| Simulation -> authentication | Drone objects, IDs, positions | Agents are created and enrolled | Registered agents/public keys | `services/swarm.py:build_secure_swarm`, `services/auth_coordinator.py:enroll` |
| Authentication -> communication | D2DAP M1/M2 and credentials | Freshness, signatures, shares, and verifier are checked | Session record/key | `security/d2dap/agent.py:initiate/respond/complete` |
| Communication -> traffic | Sessions and normal sources | `Packet` objects are emitted and optionally sealed | Delivered/dropped records | `simulation/engine.py:step`, `services/secure_transport.py` |
| Traffic -> attack | Running swarm and request | Attack object adds/transforms packet traffic | Attack packets/evidence | `attacks/manager.py`, `attacks/external.py`, `attacks/insider.py` |
| Packets -> IDS | Finalized `TrafficLog` records | Records become source/window features | `p_attack`, class, `p_insider` | `ids/features.py:extract_windows`, `services/monitor.py:_ids` |
| IDS -> trust | Model output plus auth/verdicts | Evidence changes decayed alpha/beta state | `TrustUpdate` | `trust/engine.py:TrustEngine.update` |
| Trust -> policy | Trust update/evidence | Bands, hysteresis, and hard rules select state | `PolicyDecision` | `policy/engine.py:PolicyEngine.evaluate` |
| Policy -> response | State transition | Receiver filter applies action | Drops/rate limits/session actions | `policy/enforcement.py:PolicyEnforcer` |
| Runtime -> dashboard | Python snapshots | FastAPI serializes state; browser polls | Tiles/table/charts/events | `services/live.py`, `api/main.py`, `frontend/app.js` |

## 3. Frontend from zero

`frontend/index.html` is a static HTML document. It creates the controls and empty
containers: top controls, metric tiles, topology SVG, drone table, trust chart, IDS
chart, attack form, and event list. It loads `/static/styles.css` and
`/static/app.js`.

`frontend/styles.css` only controls presentation. It does not own simulation state or
make requests.

`frontend/app.js` is one vanilla JavaScript file. There is no React, Next.js, Vue,
client router, Redux store, WebSocket, or frontend build step.

| Function | Purpose/input | Output/caller | Important variables |
|---|---|---|---|
| `api(path, opts={})` | `fetch()` a JSON endpoint | Promise of parsed JSON; called by handlers and `refresh` | `path`, `opts`, `res` |
| `renderTiles(m)` | `/api/metrics` object | Replaces `#tiles`; called by `refresh` | delivered ratio, `m.states` |
| `renderTopology(st)` | `/api/state` object | Redraws SVG lines/circles | active drones, `st.edges`, scaled positions |
| `renderTable(st)` | `/api/state` object | Replaces rows and target options | drone summaries, selected IDs |
| `renderCharts(tr)` | `/api/trust` object | Draws SVG trust/probability paths | `tr.series`, `tr.bands` |
| `renderEvents(evts)` | incremental event array | Prepends event list; max 200 DOM entries | `lastEventId`, event fields |
| `refresh()` | no argument | Fetches four snapshots and calls renderers | `st`, `met`, `tr`, `evts` |
| `init()` | no argument | Loads attack kinds, handlers, first refresh, polling | DOM handlers, interval |

`renderTopology()` receives current simulator positions and edges. It linearly maps x/y
to SVG coordinates; z is not drawn. `renderCharts()` uses hand-built SVG, not a chart
library. It highlights selected drones or up to four lowest-trust drones.

## 4. Dashboard element reference

| Element | Backend source | Calculation | Endpoint/frontend |
|---|---|---|---|
| Drones/Seed/System/Speed | DOM inputs | Values validated by `LiveConfig` on Start | `POST /api/simulation/start`, Start handler |
| Start | `LIVE.start()` | Builds a fresh run and starts thread | `main.start`, `api.js` handler |
| Stop | `LIVE.stop()` | `_running=False`, joins thread | `main.stop`, `api.js` handler |
| Simulation time | `SimulationClock.now_s` | Virtual ms / 1000 | `/api/metrics`, `renderTiles` |
| Packets delivered | `NetworkCounters` | delivered / (delivered+dropped) | `/api/metrics`, `renderTiles` |
| D2DAP sessions/failures | `CoordinatorCounters` | completed successes / failures | `/api/metrics`, `renderTiles` |
| IDS alerts | `SecurityMonitor.alerts` | count of `p_attack >= 0.5` alerts | `/api/metrics`, `renderTiles` |
| Policy decisions | `policy.decisions` | state-transition count | `/api/metrics`, `renderTiles` |
| Restricted or worse | state counter | restrict+reauthenticate+quarantine | `/api/metrics`, `renderTiles` |
| Quarantined | state counter | count of `quarantine` | `/api/metrics`, `renderTiles` |
| Monitor ms/window | `MonitorStats.processing_ms` | mean of last 30 samples | `/api/metrics`, `renderTiles` |
| Topology | `network.topology()` | active pair within channel range | `/api/state`, `renderTopology` |
| Drone table | `Drone.summary()` | current role/auth/trust/state/battery/session fields | `/api/state`, `renderTable` |
| CRPs | D2DAP agent | remaining challenge-list length | `/api/state`, `renderTable` |
| Trust chart | `TrustUpdate.new` | recent 180 simulation seconds | `/api/trust`, `renderCharts` |
| ML probability chart | `Evidence.attack_prob` | stored `1-P(benign)` per source/window | `/api/trust`, `renderCharts` |
| Attack selector | `ATTACK_TYPES` excluding eavesdropping | kind/STRIDE/insider list | `/api/attacks/kinds`, `init` |
| Target selector | registered non-radio drones | derived from current state | `/api/state`, `renderTable` |
| Duration/Rate | DOM input | Pydantic bounds, then `AttackSpec` | `/api/attacks`, Launch handler |
| Launch | `AttackManager.launch()` | schedules an attack | `/api/attacks`, Launch handler |
| Recent events | bounded `LIVE._events` deque | incremental IDs | `/api/events?since=N`, `renderEvents` |

## 5. Exact Start flow

When Start is clicked, `frontend/app.js` reads the four controls and sends:

```json
POST /api/simulation/start
{"num_drones":10,"seed":42,"variant":"adaptive","speed":2}
```

`backend/app/api/main.py:start()` receives Pydantic `LiveConfig` and calls
`LIVE.start(config)`. `LiveSimulation.start()` first calls `self.stop()`, constructs a
`ScenarioConfig`, chooses `Variant(config.variant)`, and calls
`scenario.build_variant()`.

`build_variant()` creates `SimulationConfig` and calls `build_secure_swarm()`. That
function creates `RandomStreams`, `SimulationEngine`, `D2DAPSystem`,
`SecureTransport`, `AuthCoordinator`, and `TrafficLog`; creates/joins the swarm; and
enrolls every drone through the Control Server. For IDS/trust/policy variants,
`install_framework()` loads the IDS artifact and installs `SecurityMonitor`.

`LIVE.start()` stores the swarm/monitor/attack manager, attaches an auth listener,
records a system event, sets `_running=True`, and starts daemon thread `_loop()`.
`_loop()` repeatedly calls `step(1)` and sleeps using tick duration divided by speed.

The browser receives no push message from Start; the next one-second `refresh()` reads
the backend snapshots.

### Beginner explanation

Start discards the old automatic run, builds a fresh seeded swarm, registers the
drones, connects the security monitor, and starts a worker that advances virtual time.
The browser asks the backend for the current state every second.

### Viva answer

“Sir, when I click Start, `app.js` sends the configuration to
`POST /api/simulation/start`. FastAPI passes it to `LiveSimulation.start()`, which
builds a new `SecureSwarm` through `build_variant()` and `build_secure_swarm()`. The
swarm creates the engine, drones, D2DAP registration, secure transport, and selected
IDS/trust/policy monitor. A background thread advances virtual ticks, and the browser
reads snapshots by one-second HTTP polling.”

## 6. Exact Stop flow

`btn-stop` sends `POST /api/simulation/stop`. `main.stop()` calls `LIVE.stop()`.
`LiveSimulation.stop()` sets `_running=False`, joins the live thread for up to five
seconds if it is alive, and sets `_thread=None`.

Stop does not destroy the `LiveSimulation` singleton, clear the swarm, erase event
history, or close a stream. The current state remains in memory. `/api/simulation/step`
can still advance it because `LIVE.step()` does not require `_running=True`. The next
Start stops again, then replaces config/swarm/monitor/attacks and clears live events.

The background thread keeps the HTTP request responsive while simulation progresses. It
is one thread, not a separate process, WebSocket task, or SSE stream.

### Viva answer

“Stop changes the `_running` flag and joins the worker thread with a five-second
timeout. It stops automatic advancement but preserves the in-memory snapshot. The next
Start creates a fresh swarm and clears the live event history.”

## 7. One simulation tick

```text
SimulationEngine.step()
  1. clock.advance(tick_ms)
  2. mobility.step() for active drones
  3. each source.generate(now, dt_ms)
  4. engine.transmit(packet)
       -> AuthCoordinator/SecureTransport send hook
       -> DroneNetwork.send()
       -> WirelessChannel range/loss/latency
       -> event queue
  5. DroneNetwork.deliver_due(now)
       -> PolicyEnforcer filter
       -> D2DAP/data handler
       -> TrafficLog observer
  6. battery update
  7. tick hooks: monitor, attack manager, rekey/expiry
```

`SimulationEngine.step()` advances the virtual clock, moves drones, generates normal
traffic, transmits packets, delivers due packets, updates battery, and invokes tick
hooks. `AttackManager._tick()` drives attack lifecycle. `SecurityMonitor._tick()`
collects finalized records and processes complete windows.

A virtual simulation second is 1000 ms of model time; it does not require 1 wall-clock
second. Wall-clock time is the computer's real time. Speed changes the worker sleep
budget, so the same virtual tick sequence is displayed faster or slower; it does not
change tick size or packet formulas.

## 8. Drone lifecycle and roles

`SimulationEngine.create_swarm()` creates leader(s), relays, then workers. `add_drone()`
assigns an ID (`D1`, `D2`, ...), a seeded random 3D position, battery 100, trust 1.0,
NORMAL policy state, and normal traffic sources. `join()` makes it active.

If authentication is required, `build_secure_swarm()` calls
`AuthCoordinator.enroll()` for each drone. This creates a D2DAP agent/PUF and runs
Control Server registration, leaving credentials and CRPs on the agent.

- Leader: may issue privileged command traffic; normally D1.
- Relay: role metadata for the swarm; no multi-hop forwarding protocol is implemented.
- Worker: sends telemetry/video to a leader or reachable neighbour and receives commands.

## 9. Topology and packets

`DroneNetwork.topology()` iterates over active pairs, computes Euclidean distance, and
adds an undirected edge when `WirelessChannel.in_range(distance)` is true.
`LIVE.state()` returns current positions and `{a,b,distance_m}` edges. `renderTopology()`
scales x/y into SVG; z is not drawn.

This is the current graph used by the simulator's range checks. It is not physical RF,
multi-hop routing, interference modelling, or a real network map.

`Packet` contains `packet_id`, claimed `src`, physical/evaluation `true_src`, `dst`,
protocol, size, sequence, optional session/payload, attack metadata, and receiver-side
`auth_ok`, `integrity_ok`, `auth_failure`, and `dropped_reason`.

`PacketFactory.make()` assigns IDs and sequence numbers. `DroneNetwork.send()` counts
the attempt, handles broadcast copies, applies range/loss, and schedules delivery.
`deliver_due()` applies receiver filters, handlers, and observers.

“Packets delivered 97.7%” means:

```text
network.counters.delivered /
(network.counters.delivered + network.counters.dropped) * 100
```

It is a ratio of finalized simulated packet delivery attempts, not real Internet or RF
delivery.

## 10. D2DAP: what it is and why it is used

D2DAP is the implemented drone-to-drone mutual authentication and key agreement
protocol. It lets two registered drones prove possession of credentials and derive a
shared session key without the Control Server participating in every D2D exchange.

The Control Server performs Setup and Registration. It chooses parameters, keeps the
secret polynomial constant, issues per-challenge shares, publishes public keys, and
installs verifier values. The D2D MAKA path is in
`security/d2dap/agent.py:DroneSecurityAgent.initiate/respond/complete` and is carried
over packets by `services/auth_coordinator.py`.

### Registration

`ControlServer.register()` generates distinct 16-byte challenges. The device agent
evaluates its bound PUF and computes `a = H(response || ID)`, creates ECC secret `x`
and public `Y`, and returns derived values through a direct function call. The server
evaluates a degree-one Shamir polynomial to issue `b`, computes `V = H(A || ID)`,
publishes `Y`, and installs `DroneCredentials`.

### M1 and M2

The initiator chooses an unused challenge, gets `a_i` from its PUF, obtains `b_i`,
derives an ECC shared key, encrypts `{a_i,b_i,T_i}`, signs the encrypted body, and
sends M1. The responder resolves the peer, decrypts, checks freshness and signature,
chooses its challenge, performs revocation-list and Shamir/verifier checks, and returns
encrypted/signed M2. The initiator performs the matching checks and derives the same
session key. A short session ID is derived from the key.

```text
Drone A / initiator                         Drone B / responder
       |--- AUTH_REQUEST M1 ----------------------->|
       |    encrypted share body + signatures        |
       |                                              | decrypt/freshness/signature
       |                                              | revocation + Shamir checks
       |<-- AUTH_RESPONSE M2 ------------------------|
       |    encrypted response body + signatures      |
       | check freshness/RL/Shamir/signature          |
       |====== derive H(a_i || a_j || T_i || T_j) ====|
       |             install session                  |
```

`initiate()` returns serialized M1, `respond()` returns M2 plus a responder session,
and `complete()` returns the initiator session. Failures raise `ProtocolAbort` with
freshness, signature, secret mismatch, CRP exhausted, replay, unknown peer, or malformed
reasons. `AuthCoordinator` publishes `AuthEvent` and updates counters.

### D2DAP versus SecureTransport

D2DAP answers “who are you and can we agree on a key?” `SecureTransport` answers “can
later data be encrypted, integrity-checked, and replay-checked?” It derives an AES-GCM
data key, authenticates headers as AAD, and verifies at the receiver. Both are needed:
authentication alone does not protect subsequent telemetry; encryption without an
authenticated key exchange does not establish whose key it is. Broadcast heartbeats
are intentionally not pairwise sealed.

## 11. Software PUF and CRP

CRP means challenge-response pair. A challenge is an input and the device-specific PUF
response is its output. The project provisions 128-bit challenges. `XORArbiterPUF`
models additive delay weights and optional noise/majority voting. `BoundPUF` restricts
evaluation to the owning logical drone ID.

The default PUF is seeded software state, not silicon, SRAM, FPGA, or hardware.

### Professor-ready answer

“Sir, we do not claim a physical PUF. Because this is software-only, we expose a
hardware-independent PUF interface and implement an XOR-Arbiter additive-delay model.
Each simulated device receives different seeded weights, and `BoundPUF` models the rule
that only the owner can query it. This lets us test D2DAP and CRP consumption, but it
cannot prove physical unclonability, hardware modelling resistance, or hardware timing.”

## 12. Implemented attacks

| Name | Class | Type | STRIDE | Behaviour |
|---|---|---|---|---|
| spoofing | `external.SpoofingAttack` | external | S | Claims target identity; emits forged data and some forged auth requests |
| replay | `external.ReplayAttack` | external | S,D | Captures target auth/data and replays fresh/stale variants |
| tampering | `external.TamperingAttack` | external | T | Flips payload bits; authenticated data fails integrity |
| dos_auth_flood | `external.DosAuthFloodAttack` | external | D | Sends crafted auth requests to force responder work |
| impersonation | `external.ImpersonationAttack` | external | S,E | Attempts identity impersonation |
| unauthorized_access | `external.UnauthorizedAccessAttack` | external | E | Attempts data/control access without authorization |
| eavesdropping | `external.EavesdroppingAttack` | external | I | Simulates disclosure; excluded from traffic selector |
| flooding | `insider.FloodingAttack` | insider | D | Legitimate node sends excessive traffic |
| privilege_escalation | `insider.PrivilegeEscalationAttack` | insider | E | Non-leader sends privileged commands |
| abnormal | `insider.AbnormalTrafficAttack` | insider | D | Legitimate node emits erratic high-rate/random-peer traffic |

The authoritative registry is `attacks/manager.py:ATTACK_TYPES`. The IDS sees packet
headers and receiver verdicts, not attack ground truth. `AttackEvidence` is for
evaluation and demonstration reporting.

## 13. Exact spoofing Launch flow

For spoofing, target D2, duration 30 seconds, rate 20 packets/second:

| Stage | File/class/function | Input | Output |
|---|---|---|---|
| Browser | `frontend/app.js`, `btn-attack` handler | DOM values | JSON POST |
| HTTP | `api()` | `/api/attacks` | parsed JSON/error |
| FastAPI | `api/main.py:launch` | `AttackRequest` | live-service result |
| Live service | `services/live.py:launch_attack` | request/current virtual time | `AttackSpec` and ID |
| Scheduler | `attacks/manager.py:launch` | attack spec | stored `SpoofingAttack` |
| Start | `external.py:_ExternalAttack._start` | start time reached | attacker radio/source |
| Generate | `SpoofingAttack._build` via `_RateSource.generate` | rate/current time | forged telemetry/auth packets |
| Network | `engine.transmit` -> `DroneNetwork.send` | packet objects | queue/drop/delivery |
| Observation | `TrafficLog.__call__` | finalized packets | flat records |
| Windowing | `SecurityMonitor._process` | one-second records | feature rows/evidence |
| ML | `SecurityMonitor._ids` -> `predict_proba` | feature DataFrame | probabilities/class |
| Trust | `TrustEngine.update` | `Evidence` | `TrustUpdate` |
| Policy | `PolicyEngine.evaluate` | trust update | optional decision |
| Enforcement | `PolicyEnforcer.apply/_filter` | state/action | limits, blocks, drops |
| Events | `LIVE._collect` | new alerts/decisions | event dictionaries |
| Browser | `setInterval(refresh,1000)` | endpoint snapshots | redraw |

The request sets `start_ms=now+1` and `duration_ms=30000`. The attack rate is a Poisson
mean, approximately `Poisson(rate_pps * dt_ms / 1000)`, so 20 is an expected rate, not
exactly 20 packets each second.

### Simplified professor explanation

“Launch sends an attack description to FastAPI. The live service creates a scheduled
SpoofingAttack with an external radio. It emits packets claiming to be D2. The simulator
processes them like other packets. The traffic log and receiver verdicts feed the
one-second IDS window. IDS evidence changes attribution-aware trust; policy may change
state and receiver-side enforcement changes subsequent handling. The next browser poll
shows alerts, trust, decisions, and metrics.”

## 14. ML IDS and the one-second window

The primary training data is generated by the project simulator in
`backend/app/ids/dataset.py`; it is not real drone capture. Optional NSL-KDD support
exists, but the public files are not included.

`extract_windows()` creates one row per `(claimed source, one-second window)`. Features
are:

```text
tx_count, rx_count, bytes_total, size_mean, size_std, size_max,
unique_dst, iat_mean_ms, iat_std_ms,
frac_telemetry, frac_video, frac_command, frac_heartbeat, frac_auth,
auth_req_count, auth_unique_dst, auth_fail_count, auth_accept_count,
unauth_data_count, integrity_fail_count, replay_reject_count, no_session_count,
seq_dup_count, seq_backjump_count, cmd_count, src_is_leader,
verified_count, verified_cmd_count
```

The live monitor processes a window after its end plus grace period. `TrainedModel` uses
the saved pipeline from `results/models/ids_operational.joblib`. Training in
`ids/models.py` applies `log1p` to non-negative numeric values, standardisation,
balanced handling, and grouped cross-validation. Available models are Logistic
Regression, Decision Tree, Random Forest, and XGBoost.

In live inference, `SecurityMonitor._ids()` calls `predict_proba()`. The code defines:

```text
P(attack) = 1 - P(benign)
```

This is the probability mass assigned to every non-benign class. `p_insider` sums the
probabilities for `flooding`, `privilege_escalation`, and `abnormal`; the predicted
class is the maximum-probability class. An alert is appended when `p_attack >= 0.5` by
default (`MonitorConfig.ids_threshold`).

Ground truth fields `true_src`, `label`, and `attack_id` are excluded from live feature
extraction. Labels are used for dataset generation/training/evaluation, not live input.

## 15. Trust engine: actual formula

The engine stores alpha/beta evidence mass plus fixed prior values. Trust is:

```text
Trust = (alpha + prior_alpha) /
        (alpha + beta + prior_alpha + prior_beta)
```

For each window, accumulated evidence decays by `lambda=0.85`:

```text
alpha <- lambda^steps * alpha + positive_evidence
beta  <- lambda^steps * beta  + negative_evidence
```

The prior is not decayed. Registered-drone prior is alpha 4.0/beta 0.5; unknown-source
prior is 1.0/1.0. `sat(n)=1-exp(-n/3)` bounds burst effects.

With default parameters, the ML terms are:

```text
ml_normal = 1.0 * (1-p)
ml_attack = -3.0 * [
  p_ins * (attribution*multiplier
           + (1-attribution)*0.05)
  + p_ext*0.05
]
```

The other exact terms include:

```text
auth_success    = +0.5 * min(completed_MAKA, 3)
auth_failure    = -2.0 * sat(failures) * unattributed_factor
violation       = -2.0 * sat(integrity/replay/unauth/no-session count)
authz_violation = -2.0 * sat(non-leader verified-command count) * multiplier
reauth_success  = +4.0
```

The repeat-offender multiplier is `min(3.0, 1+0.15*bad_windows_in_history)`. The
anomaly component uses an EWMA of verified traffic; with ML it only corroborates
insider probability using a floor of 0.2, rather than independently escalating.

### Illustrative numerical example

This is arithmetic using defaults, not a claim about a particular CSV row. Suppose a
registered drone has no accumulated evidence and one window has `p_attack=0.90`, all
insider, attribution 1.0, multiplier 1, and no other terms:

```text
positive = 1.0*(1-0.90) = 0.10
negative = 3.0*0.90 = 2.70
alpha = 0.10, beta = 2.70
trust = (0.10+4.0)/(0.10+2.70+4.0+0.5)
      = 4.10/7.30 = 0.562 approximately
```

That value is below 0.60 and above 0.40, so the policy band is RESTRICT. For an
outsider spoofing the same identity with zero verified attribution, the attack evidence
is discounted by 0.05. This is the anti-framing design goal; it is not a universal proof
for real deployments.

## 16. Policy and enforcement

Default graded bands:

```text
trust >= 0.80        NORMAL
0.60 <= trust < .80  MONITOR
0.40 <= trust < .60  RESTRICT
0.20 <= trust < .40  RE-AUTHENTICATE
trust < 0.20         QUARANTINE
```

Hysteresis is 0.05 while relaxing to a less severe state, reducing threshold flapping.
Repeated entry into RE-AUTHENTICATE within 60 seconds can cause quarantine. A failed
forced re-authentication causes quarantine.

Quarantine exit needs at least 20 seconds, successful re-authentication, and trust at
least `restrict+hysteresis` (0.45); the drone enters RESTRICT probation, not NORMAL.

`PolicyEnforcer` is a `DroneNetwork` receiver ingress filter. RESTRICT or worse uses a
token bucket (5 packets/second, burst 10), blocks COMMAND packets, and escalates actions.
RE-AUTHENTICATE revokes sessions and triggers fresh MAKA. QUARANTINE revokes sessions,
blocks new sessions, drops traffic, and broadcasts a notice; after probation an auth
request may pass. Receiver-side enforcement is necessary because a compromised sender
can ignore sender-side restrictions.

## 17. Complete policy example

Using the illustrative trust value 0.562, `PolicyEngine.evaluate()` records NORMAL ->
RESTRICT. `PolicyEnforcer.apply()` sets the drone state and enables rate-limiting and
privileged-command blocking. If later trust reaches 0.18, it transitions to
QUARANTINE; sessions are revoked, initiator sessions are blocked, traffic is dropped,
and a policy notice is sent. A later successful re-authentication still must satisfy
the quarantine time and 0.45 trust gate before RESTRICT probation.

## 18. Real-time updates

The exact loop is:

```javascript
setInterval(refresh, 1000);
```

Each refresh requests `/api/state`, `/api/metrics`, `/api/trust`, and
`/api/events?since=<lastEventId>` concurrently. The first returns current drones,
positions, edges, active attacks, and status. The second returns counters/states and
timings. The third returns trust/probability series and bands. The fourth returns only
new bounded event records.

This is polling because the browser initiates repeated HTTP requests. The repository
has no WebSocket, SSE, or long-poll route. `lastEventId` is updated by
`renderEvents()` so records are not rendered twice.

## 19. Complete data-flow diagram

```text
User click
  -> browser DOM values
  -> frontend/app.js fetch JSON
  -> FastAPI route
  -> LiveSimulation method
  -> SecureSwarm / SimulationEngine
  -> DroneNetwork and Packet objects
  -> D2DAP coordinator + SecureTransport
  -> TrafficLog finalized records
  -> SecurityMonitor one-second window
  -> TrainedModel probabilities/classes
  -> Evidence
  -> TrustEngine TrustUpdate
  -> PolicyEngine PolicyDecision
  -> PolicyEnforcer receiver filter/actions
  -> LIVE state, metrics, trust history, events
  -> FastAPI JSON
  -> browser render functions
```

The boundaries carry, respectively: JSON configuration; Pydantic requests; runtime
objects; packets; auth/integrity verdicts; flat records; feature rows; model arrays;
evidence dataclasses; trust audit records; policy records; filter results; and JSON
snapshots.

## 20. Normal-operation trace

1. Start invokes `LiveSimulation.start()` and creates `SecureSwarm`.
2. `SimulationEngine.create_swarm()` creates and joins drones.
3. Control Server registration gives agents credentials and CRPs.
4. Normal sources create heartbeat, telemetry, video, and leader-command packets.
5. On first protected unicast without a session, `AuthCoordinator._send_hook()` holds
   the packet and starts D2DAP M1.
6. The responder processes M1; the initiator processes M2; both install sessions.
7. Held traffic is released and `SecureTransport` seals it with AES-GCM.
8. `DroneNetwork.deliver_due()` applies filters/handlers and `TrafficLog` records fate.
9. The monitor creates benign-looking feature rows and normally keeps policy NORMAL.
10. Browser polling displays the snapshots.

## 21. Attack trace summary

1. Launch creates an `AttackSpec` and stores a concrete attack object.
2. At its start time, an external attack may add an `X-...` node; an insider attack uses
   a legitimate node.
3. The attack generates or alters actual simulator `Packet` objects.
4. D2DAP, transport, and policy filters determine receiver-side results.
5. TrafficLog stores observable and evaluation-only fields.
6. The monitor aggregates only allowed observable information for live IDS inference.
7. Trust discounts evidence not cryptographically bound to the claimed identity.
8. Policy escalates only when its band or hard rules require it.
9. The receiver enforces the resulting action.
10. Events and snapshots appear on the next poll.

## 22. What belongs to which research category

| Category | Project content |
|---|---|
| Reference D2DAP work | D2D authentication concept, ECC/PUF/Shamir structure, MAKA logic |
| PUF concept | Hardware-independent interface and software XOR-Arbiter model; not hardware |
| ML literature | IDS framing, multiclass classification, models, metrics/evaluation discipline |
| This implementation | Drone simulator, channel, packet transport, attacks, data generation, dashboard, experiments |
| Proposed contribution | Attribution-aware decayed trust, graded policy with hysteresis/hard rules, forced re-authentication, receiver-side enforcement, integrated response |

Do not present D2DAP, PUF, generic ML classifiers, STRIDE, or Beta reputation as newly
invented by this project.

## 23. Limitations to say clearly

| Unsafe claim | Accurate statement |
|---|---|
| “We built a physically unclonable PUF.” | We model a PUF in software; physical unclonability is not established. |
| “This is a real drone network.” | It is a deterministic software simulation of drones, links, traffic, and attacks. |
| “We measured real RF security.” | Range, latency, loss, and mobility are software abstractions. |
| “We proved energy efficiency.” | No hardware energy measurement is implemented. |
| “Our timing is Raspberry Pi timing.” | Timing is host-dependent and uses software cryptography. |
| “We reproduced formal D2DAP proof/AVISPA.” | The project tests protocol behaviour; it does not reproduce those formal runs. |
| “The IDS generalizes to real IoD traffic.” | Main scores are on simulator-generated D2D-SIM data; real generalization is not established. |
| “The monitor is fully distributed.” | It is leader-hosted and assumes an honest leader. |

## 24. Professor demonstration script

### Preparation

From the project root, run:

```powershell
python scripts\run_dashboard.py
```

Open `http://127.0.0.1:8000`. The adaptive variant needs
`results/models/ids_operational.joblib`; if unavailable, the live service falls back
to `no_ml` and displays a notice.

### Practice run

1. Set Drones `8`, Seed `42`, System `D: Full adaptive`, Speed `2`.
2. Click Start.
3. Say: “The browser sent the configuration to FastAPI. The backend built a fresh
   seeded swarm, registered drones, installed D2DAP and the monitor, and started a
   background simulation loop.”
4. Show topology. Say: “These are active simulated drones. An edge means current
   Euclidean distance is within modeled communication range; it is not a physical RF
   graph.”
5. Show Auth and CRPs. Say: “CRPs are remaining software challenge entries. A first
   protected unicast can trigger packet-level MAKA, after which the session is used for
   AES-GCM data-plane protection.”
6. Show trust. Say: “Trust is a decayed Beta reputation combining ML, authentication,
   receiver verdicts, attribution, and anomaly evidence.”
7. Choose Attack `spoofing`, target `D2`, Duration `30`, Rate `20`; click Launch.
8. Say: “The UI sent an AttackRequest. The backend created a SpoofingAttack with an
   external radio, which emits an expected-rate stream claiming D2.”
9. Show IDS. Say: “The monitor closes one-second windows, extracts observable features,
   calls `predict_proba()`, and displays `1-P(benign)`.”
10. Show trust/state. Say: “Unverified spoofed packets are not fully attributable to D2,
    so attribution-aware trust discounts them to reduce framing risk. A verified
    insider attack is treated more strongly.”
11. Show policy/events. Say: “The policy state changes only when its trust band or hard
    rules require it. Enforcement is receiver-side: rate-limit, block commands, revoke
    sessions, or quarantine.”
12. Finish: “All values come from running backend objects through one-second HTTP
    polling. They are simulated research measurements, not hardware measurements.”

## 25. Short explanations for viva

### 30 seconds

“This is a software simulation of adaptive security for drone-swarm communication.
D2DAP authenticates drones and establishes session keys. Simulated traffic and attacks
are processed by an ML IDS. Its evidence is fused with authentication and packet
verification in an attribution-aware trust engine. A graded policy changes the receiver
response from monitoring to restriction, re-authentication, or quarantine. The
dashboard is vanilla JavaScript polling a FastAPI backend.”

### 2 minutes

Explain the same pipeline, then distinguish D2DAP from SecureTransport and state that
traffic consists of Python `Packet` objects passed through a modeled range/loss channel.
Mention one-second features, `P(attack)=1-P(benign)`, Beta trust, and receiver-side
enforcement. End with software-only limitations.

### 5 minutes (default)

“The problem is that authentication alone tells us whether a node has valid credentials,
but not whether an authenticated node is behaving safely. Our simulator creates a seeded
drone swarm with modeled mobility, channel range/loss, normal traffic, D2DAP registration,
and session establishment. On first protected unicast, packet-level MAKA authenticates
the peers and derives a session key; SecureTransport then uses AES-GCM for unicast data
integrity, confidentiality, and replay checks.

We inject external and insider attacks into simulator packets. The traffic log records
receiver-observable outcomes. Every second, `SecurityMonitor` aggregates features per
claimed source, such as rate, sizes, protocol mix, authentication failures, integrity
failures, replay verdicts, sequence behaviour, and verified traffic. The trained model
returns multiclass probabilities; binary attack probability is one minus benign.

The main contribution is `TrustEngine`: a decayed Beta reputation with attribution-aware
evidence. Cryptographically verified insider behaviour is strong identity-bound
evidence, while spoofed unverified traffic is discounted to reduce framing. The
`PolicyEngine` maps trust through NORMAL, MONITOR, RESTRICT, RE-AUTHENTICATE, and
QUARANTINE with hysteresis and hard rules. `PolicyEnforcer` runs at receivers, where a
compromised sender cannot bypass it.

The dashboard is static HTML/CSS/JavaScript. It sends JSON to FastAPI and polls state,
metrics, trust, and events every second. This establishes simulation results; it does
not establish physical PUF security, real RF security, hardware energy efficiency, or
real-world IDS generalization.”

### 10 minutes

Use the five-minute answer, then demonstrate Start, topology, D2DAP/CRPs, attack launch,
IDS probability, trust chart, policy event, and event explanation. Open
`live.py`, `engine.py`, `auth_coordinator.py`, `agent.py`, `features.py`, `monitor.py`,
`trust/engine.py`, and `policy/engine.py` while answering.

## 26. Twenty files to understand

### Tier 1 — must know

1. `frontend/index.html` — controls and display containers.
2. `frontend/app.js` — fetch, handlers, polling, rendering.
3. `backend/app/api/main.py` — HTTP contract.
4. `backend/app/services/live.py` — live singleton, thread, snapshots, attack launch.
5. `backend/app/experiments/scenario.py` — variant/swarm assembly.
6. `backend/app/services/swarm.py` — engine/D2DAP/transport wiring.
7. `backend/app/simulation/engine.py` — tick lifecycle.
8. `backend/app/simulation/network.py` — queue, filters, range, delivery.
9. `backend/app/security/d2dap/agent.py` — M1/M2 endpoint.
10. `backend/app/services/auth_coordinator.py` — packet-level MAKA orchestration.
11. `backend/app/services/monitor.py` — IDS-to-policy pipeline.
12. `backend/app/trust/engine.py` — contribution and formula.
13. `backend/app/policy/engine.py` — state machine.
14. `backend/app/policy/enforcement.py` — receiver-side response.

### Tier 2 — should know

15. `backend/app/security/puf.py` — software PUF and BoundPUF.
16. `backend/app/security/d2dap/control_server.py` — setup/registration.
17. `backend/app/services/secure_transport.py` — AES-GCM data plane.
18. `backend/app/ids/features.py` — feature list/windows.
19. `backend/app/ids/models.py` — preprocessing/training/inference wrapper.
20. `backend/app/attacks/manager.py`, `external.py`, `insider.py` — attack framework.

Recommended reading order: domain models -> simulator -> D2DAP/transport -> IDS ->
trust/policy -> monitor -> live API -> frontend -> tests/demo.

## 27. Viva questions and answers

### Basic

1. **What problem does this solve?**
   - Short: It joins authentication, IDS, trust, and response for simulated drone traffic.
   - Detail: D2DAP handles identity; IDS handles behaviour; trust/policy decide response.
   - Code: `services/monitor.py`, `trust/engine.py`, `policy/engine.py`.
2. **What is D2DAP?**
   - Short: D2D mutual authentication and key agreement.
   - Detail: Agents exchange encrypted/signed M1/M2 and derive a session key.
   - Code: `security/d2dap/agent.py`.
3. **What is a CRP?**
   - Short: A PUF challenge and its device-specific response.
   - Detail: Challenges are 16-byte values used during registration/MAKA.
   - Code: `security/puf.py`, `d2dap/control_server.py`.
4. **Is the PUF physical?**
   - Short: No, it is a software model.
   - Detail: Seeded XOR-Arbiter weights and `BoundPUF` model device binding.
   - Code: `security/puf.py`.
5. **What does the IDS predict?**
   - Short: A multiclass behaviour class and derived attack probability.
   - Detail: `p_attack=1-P(benign)`.
   - Code: `ids/features.py`, `services/monitor.py:_ids`.
6. **What does Start do?**
   - Short: Sends configuration, creates a fresh swarm, starts the simulation thread.
   - Code: `frontend/app.js`, `services/live.py:start`.
7. **What does Stop do?**
   - Short: Clears the run flag and joins the worker.
   - Code: `services/live.py:stop`.
8. **Are packets real network packets?**
   - Short: No, Python `Packet` objects in a modeled queue.
   - Code: `models/packet.py`, `simulation/network.py`.
9. **What is the frontend?**
   - Short: Vanilla HTML/CSS/JavaScript; no React/build step.
   - Code: `frontend/`.
10. **How are updates delivered?**
    - Short: One-second HTTP polling.
    - Code: `frontend/app.js:init`, `api/main.py`.

### Intermediate

11. **Why both D2DAP and SecureTransport?**
    - Short: D2DAP establishes identity/key; SecureTransport protects later data.
    - Code: `d2dap/agent.py`, `services/secure_transport.py`.
12. **Why group features by claimed source?**
    - Short: Evidence is associated with identity claims while attribution is tracked separately.
    - Code: `ids/features.py`, `trust/engine.py`.
13. **Why exclude ground truth?**
    - Short: To prevent label leakage into live detection.
    - Code: `models/packet.py`, `ids/features.py`.
14. **What is P(attack)?**
    - Short: `1-P(benign)` from multiclass probabilities.
    - Code: `SecurityMonitor._ids`.
15. **What triggers an alert?**
    - Short: `p_attack >= 0.5` by default.
    - Code: `MonitorConfig.ids_threshold`, `monitor.py:_process`.
16. **What is trust?**
    - Short: `(alpha+prior_alpha)/(alpha+beta+prior_alpha+prior_beta)` after decayed updates.
    - Code: `trust/engine.py`.
17. **Why attribution awareness?**
    - Short: To reduce framing an honest identity with spoofed, unverified traffic.
    - Code: `trust/engine.py:update`.
18. **Why receiver-side enforcement?**
    - Short: A malicious sender cannot bypass a receiver's filter.
    - Code: `policy/enforcement.py`.
19. **What is hysteresis?**
    - Short: A recovery margin that reduces state flapping.
    - Code: `policy/engine.py:_with_hysteresis`.
20. **What happens at quarantine?**
    - Short: Sessions revoked, new sessions blocked, traffic dropped, notice broadcast.
    - Code: `policy/enforcement.py:apply/_filter`.

### Difficult

21. **Does D2DAP prove a drone is benign?**
    - Short: No; it proves credential possession, not safe behaviour.
    - Code: `attacks/insider.py`, `services/monitor.py`.
22. **Can spoofing quarantine an honest drone?**
    - Short: Attribution-aware fusion discounts unverified evidence for registered identities.
    - Detail: This is a tested design goal in simulation, not a universal proof.
    - Code: `trust/engine.py:update`.
23. **What is authentication latency?**
    - Short: Measured Python compute plus simulated network delay in `AuthResult`.
    - Code: `security/d2dap/service.py:AuthResult.latency_ms`.
24. **Does compute timing alter virtual time?**
    - Short: No; fixed simulated compute delay is kept separate from wall-clock measurement.
    - Code: `auth_coordinator.py:SIMULATED_COMPUTE_DELAY_MS`.
25. **What is topology?**
    - Short: Active pairs within modeled range, not full routing.
    - Code: `simulation/network.py:topology`.
26. **What data does IDS use?**
    - Short: Observable headers and receiver verdict aggregates, not labels/attack IDs.
    - Code: `ids/features.py`.
27. **Why can an insider pass authentication?**
    - Short: A compromised legitimate holder has valid credentials.
    - Code: `attacks/insider.py`, `d2dap/agent.py`.
28. **Biggest deployment limitation?**
    - Short: Leader-hosted monitor and no physical/RF validation.
    - Code: `services/monitor.py`, `docs/FINAL_PROJECT_AUDIT.md`.
29. **Is high IDS accuracy real-drone accuracy?**
    - Short: No; main scores are on simulator-generated D2D-SIM data.
    - Code: `ids/dataset.py`, `docs/FINAL_PROJECT_AUDIT.md`.
30. **What would you improve next?**
    - Short: Physical PUF/fuzzy extractor, real/emulated IoD data, distributed monitoring, replay hardening, formal verification.
    - Code: `docs/FINAL_PROJECT_AUDIT.md:Future work`.

## 28. Final safe summary

We built a reproducible software simulation integrating D2DAP authentication, AES-GCM
sessions, simulated drone traffic/attacks, a multiclass ML IDS, attribution-aware trust,
adaptive policy, receiver-side enforcement, experiments, and a live dashboard.

Start sends configuration to FastAPI; `LiveSimulation` builds a fresh seeded swarm,
registers agents, installs security layers, starts a tick thread, and exposes snapshots.
Launch sends an `AttackRequest`; the manager creates a scheduled attack; the engine
generates packets; the monitor creates evidence, trust updates, policy decisions, and
events.

We may claim an implemented and experimentally evaluated software framework and a
proposed adaptive trust/policy integration. We may not claim physical PUF security, real
drone deployment, real RF security, hardware energy efficiency, formal proof
reproduction, or real-world IDS generalization.
