"""Virtual simulation clock and wall/CPU timers.

The *simulation clock* drives protocol timestamps (D2DAP ``T_i``) and traffic so that
experiments are deterministic. *Timers* measure real software execution cost on the
machine running the simulation (they are what we report as latency / CPU time).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


class SimulationClock:
    """Monotonic virtual clock in integer milliseconds."""

    def __init__(self, start_ms: int = 0) -> None:
        if start_ms < 0:
            raise ValueError("start_ms must be non-negative")
        self._now_ms = start_ms

    @property
    def now_ms(self) -> int:
        return self._now_ms

    @property
    def now_s(self) -> float:
        return self._now_ms / 1000.0

    def advance(self, delta_ms: int) -> int:
        """Advance the clock by ``delta_ms`` (must be >= 0) and return the new time."""
        if delta_ms < 0:
            raise ValueError("clock cannot go backwards")
        self._now_ms += delta_ms
        return self._now_ms

    def set(self, t_ms: int) -> None:
        """Jump forward to ``t_ms`` (used by attack scripts to model delayed replays)."""
        if t_ms < self._now_ms:
            raise ValueError("clock cannot go backwards")
        self._now_ms = t_ms


@dataclass
class TimingResult:
    """Wall-clock and CPU time of a measured block, in nanoseconds."""

    wall_ns: int = 0
    cpu_ns: int = 0

    @property
    def wall_ms(self) -> float:
        return self.wall_ns / 1e6

    @property
    def cpu_ms(self) -> float:
        return self.cpu_ns / 1e6


@dataclass
class Stopwatch:
    """Context manager measuring wall (perf_counter) and process CPU time."""

    result: TimingResult = field(default_factory=TimingResult)
    _w0: int = 0
    _c0: int = 0

    def __enter__(self) -> Stopwatch:
        self._w0 = time.perf_counter_ns()
        self._c0 = time.process_time_ns()
        return self

    def __exit__(self, *exc: object) -> None:
        self.result.wall_ns += time.perf_counter_ns() - self._w0
        self.result.cpu_ns += time.process_time_ns() - self._c0
