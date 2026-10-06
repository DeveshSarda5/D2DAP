"""D2DAP configuration (see ``docs/d2dap-implementation-mapping.md``)."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.security.crypto import SecurityLevel


class PUFConfig(BaseModel):
    """Software PUF model settings (SOFTWARE PUF SIMULATION)."""

    model: str = Field("xor_arbiter", pattern="^(xor_arbiter|ideal)$")
    noise_sigma: float = Field(0.0, ge=0)
    majority_votes: int = Field(1, ge=1)
    xor_k: int = Field(4, ge=1, le=16)
    stages: int = Field(128, ge=8)


class D2DAPConfig(BaseModel):
    """Protocol parameters."""

    security_level: SecurityLevel = SecurityLevel.L128
    #: Number of one-time challenge-response pairs provisioned per drone (m).
    crp_count: int = Field(32, ge=1, le=4096)
    #: Freshness window Delta T in milliseconds.
    delta_t_ms: int = Field(2000, ge=1)
    #: How the responder finds the initiator's public key (mapping item 19).
    peer_resolution: str = Field("trial", pattern="^(trial|hint)$")
    #: Optional responder replay cache (our hardening; OFF = faithful to the paper).
    replay_cache: bool = False
    puf: PUFConfig = PUFConfig()
