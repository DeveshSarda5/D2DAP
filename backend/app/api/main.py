"""FastAPI application: REST API over the live simulation + static dashboard.

uvicorn app.api.main:app --port 8000      (or: python scripts/run_dashboard.py)
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.attacks.manager import ATTACK_TYPES, TRAFFIC_ATTACKS
from app.experiments.recorder import REPO_ROOT
from app.services.live import LIVE, AttackRequest, LiveConfig

FRONTEND = REPO_ROOT / "frontend"

app = FastAPI(title="Adaptive Trust-Aware Drone Security", version=__version__)


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__}


@app.post("/api/simulation/start")
def start(config: LiveConfig, background: bool = True) -> dict[str, Any]:
    return LIVE.start(config, background=background)


@app.post("/api/simulation/stop")
def stop() -> dict[str, Any]:
    LIVE.stop()
    return LIVE.status()


@app.post("/api/simulation/step")
def step(ticks: int = Query(10, ge=1, le=10_000)) -> dict[str, Any]:
    """Advance the simulation deterministically (tests, paused demos)."""
    LIVE.step(ticks)
    return LIVE.status()


@app.get("/api/state")
def state() -> dict[str, Any]:
    return LIVE.state()


@app.get("/api/events")
def events(since: int = 0) -> list[dict[str, Any]]:
    return LIVE.events(since)


@app.get("/api/trust")
def trust() -> dict[str, Any]:
    return LIVE.trust_history()


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    return LIVE.metrics()


@app.get("/api/attacks/kinds")
def attack_kinds() -> list[dict[str, Any]]:
    return [{"kind": k, "stride": "".join(s.value for s in ATTACK_TYPES[k].stride),
             "insider": ATTACK_TYPES[k].insider} for k in TRAFFIC_ATTACKS]  # fmt: skip


@app.post("/api/attacks")
def launch(req: AttackRequest) -> dict[str, Any]:
    try:
        return LIVE.launch_attack(req)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"cannot launch attack: {exc}") from exc


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


if FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND), name="static")
