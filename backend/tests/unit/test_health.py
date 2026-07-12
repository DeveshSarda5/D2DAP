"""Smoke tests for the Phase 0 backend foundation."""

from app.main import app


def test_health_endpoint_is_registered() -> None:
    """The health endpoint should be available on the FastAPI app."""
    route_paths = {route.path for route in app.routes}

    assert "/health" in route_paths
