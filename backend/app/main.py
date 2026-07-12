"""Application entry point for the backend service."""

from fastapi import FastAPI

app = FastAPI(title="D2DAP", version="0.1.0")


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return a simple health status payload."""
    return {"status": "ok"}
