"""Tests for core infrastructure: RNG streams, clock, config loading, logging."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from pydantic import BaseModel

from app.core.clock import SimulationClock, Stopwatch
from app.core.config_loader import build_model, deep_merge, dump_model, load_yaml
from app.core.errors import ConfigError
from app.core.logging import JsonFormatter, configure_logging, get_logger
from app.core.rng import DeterministicRandomSource, RandomStreams, stable_hash


class TestRandomStreams:
    def test_same_seed_same_stream(self) -> None:
        a = RandomStreams(42).numpy("mobility").random(5)
        b = RandomStreams(42).numpy("mobility").random(5)
        assert a.tolist() == b.tolist()

    def test_streams_are_independent_of_creation_order(self) -> None:
        s1 = RandomStreams(7)
        s1.numpy("other").random(100)  # consuming another stream must not shift "traffic"
        x = s1.numpy("traffic").random(3)
        y = RandomStreams(7).numpy("traffic").random(3)
        assert x.tolist() == y.tolist()

    def test_different_names_differ(self) -> None:
        s = RandomStreams(1)
        assert s.numpy("a").random(3).tolist() != s.numpy("b").random(3).tolist()

    def test_stable_hash_is_deterministic(self) -> None:
        assert stable_hash("drone") == stable_hash("drone")
        assert stable_hash("drone") != stable_hash("drones")

    def test_deterministic_crypto_reproducible(self) -> None:
        a = DeterministicRandomSource(5, "keys").randbytes(48)
        b = DeterministicRandomSource(5, "keys").randbytes(48)
        c = DeterministicRandomSource(6, "keys").randbytes(48)
        assert a == b
        assert a != c
        assert len(a) == 48

    def test_randbelow_in_range_and_roughly_uniform(self) -> None:
        src = DeterministicRandomSource(3, "u")
        values = [src.randbelow(10) for _ in range(5000)]
        assert min(values) == 0
        assert max(values) == 9
        counts = [values.count(v) for v in range(10)]
        assert all(400 < c < 600 for c in counts)

    def test_randbelow_rejects_nonpositive(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            DeterministicRandomSource(0, "x").randbelow(0)

    def test_system_source_when_not_deterministic(self) -> None:
        src = RandomStreams(1, deterministic_crypto=False).crypto("k")
        assert src.randbytes(16) != src.randbytes(16)


class TestClock:
    def test_advance_and_set(self) -> None:
        clk = SimulationClock()
        assert clk.advance(150) == 150
        clk.set(1000)
        assert clk.now_ms == 1000
        assert clk.now_s == 1.0

    def test_clock_cannot_go_backwards(self) -> None:
        clk = SimulationClock(100)
        with pytest.raises(ValueError, match="backwards"):
            clk.advance(-1)
        with pytest.raises(ValueError, match="backwards"):
            clk.set(50)

    def test_stopwatch_measures_positive_time(self) -> None:
        with Stopwatch() as sw:
            sum(i * i for i in range(20000))
        assert sw.result.wall_ns > 0
        assert sw.result.wall_ms == sw.result.wall_ns / 1e6


class _Cfg(BaseModel):
    seed: int = 1
    sim: dict[str, int] = {}


class TestConfig:
    def test_deep_merge_nested(self) -> None:
        merged = deep_merge({"a": {"x": 1, "y": 2}, "b": 1}, {"a": {"y": 3}})
        assert merged == {"a": {"x": 1, "y": 3}, "b": 1}

    def test_build_model_layers(self) -> None:
        cfg = build_model(_Cfg, {"seed": 1, "sim": {"n": 5}}, {"sim": {"n": 10}})
        assert cfg.seed == 1
        assert cfg.sim == {"n": 10}

    def test_build_model_invalid_raises_config_error(self) -> None:
        with pytest.raises(ConfigError):
            build_model(_Cfg, {"seed": "not-an-int"})

    def test_yaml_roundtrip(self, tmp_path: Path) -> None:
        path = tmp_path / "c.yaml"
        dump_model(_Cfg(seed=9, sim={"n": 3}), path)
        assert load_yaml(path) == {"seed": 9, "sim": {"n": 3}}

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            load_yaml(tmp_path / "missing.yaml")

    def test_non_mapping_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "list.yaml"
        path.write_text("- 1\n- 2\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="mapping"):
            load_yaml(path)


class TestLogging:
    def test_json_log_file_contains_fields(self, tmp_path: Path) -> None:
        log_file = tmp_path / "run.jsonl"
        configure_logging("DEBUG", json_output=False, log_file=log_file)
        get_logger("test").info("auth.success", drone="D1", latency_ms=1.5)
        for handler in logging.getLogger("app").handlers:
            handler.flush()
        record = json.loads(log_file.read_text(encoding="utf-8").strip().splitlines()[-1])
        assert record["event"] == "auth.success"
        assert record["drone"] == "D1"
        assert record["latency_ms"] == 1.5
        configure_logging("WARNING")

    def test_json_formatter_plain_record(self) -> None:
        rec = logging.LogRecord("app.x", logging.INFO, __file__, 1, "evt", None, None)
        assert json.loads(JsonFormatter().format(rec))["event"] == "evt"
