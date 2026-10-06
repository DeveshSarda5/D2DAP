"""API tests (Phase 19): the dashboard API serves live backend state."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.services.live import LIVE

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client() -> TestClient:
    c = TestClient(app)
    r = c.post("/api/simulation/start?background=false",
               json={"num_drones": 6, "seed": 5, "variant": "no_ml", "speed": 1})  # fmt: skip
    assert r.status_code == 200
    return c


def test_health(client: TestClient) -> None:
    assert client.get("/api/health").json()["status"] == "ok"


def test_state_reflects_running_simulation(client: TestClient) -> None:
    client.post("/api/simulation/step?ticks=50")
    st = client.get("/api/state").json()
    assert st["sim_time_s"] == pytest.approx(5.0)
    assert len([d for d in st["drones"] if not d["external_radio"]]) == 6
    assert all(0.0 <= d["trust_score"] <= 1.0 for d in st["drones"])
    engine = LIVE.swarm.engine  # type: ignore[union-attr]
    assert st["sim_time_s"] == engine.clock.now_s  # served from the live engine


def test_metrics_and_trust(client: TestClient) -> None:
    client.post("/api/simulation/step?ticks=30")
    m = client.get("/api/metrics").json()
    assert m["packets_sent"] > 0
    assert m["windows"] >= 5
    tr = client.get("/api/trust").json()
    assert tr["bands"]["normal"] == 0.8
    assert tr["series"]


def test_attack_launch_and_events(client: TestClient) -> None:
    kinds = {k["kind"] for k in client.get("/api/attacks/kinds").json()}
    assert "flooding" in kinds
    r = client.post("/api/attacks", json={"kind": "flooding", "target": "D3", "duration_s": 20,
                                          "rate_pps": 30})  # fmt: skip
    assert r.status_code == 200
    client.post("/api/simulation/step?ticks=200")
    events = client.get("/api/events").json()
    kinds_seen = {e["kind"] for e in events}
    assert {"system", "attack"} <= kinds_seen
    policy = [e for e in events if e["kind"] == "policy" and e["drone"] == "D3"]
    assert policy
    assert "Decision =" in policy[0]["explanation"]


def test_invalid_attack_rejected(client: TestClient) -> None:
    r = client.post("/api/attacks", json={"kind": "teleport", "target": "D3"})
    assert r.status_code == 400


def test_dashboard_page_served(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "Drone Trust Dashboard" in r.text
    assert client.get("/static/app.js").status_code == 200
