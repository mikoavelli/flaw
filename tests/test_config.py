"""Tests for configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from flaw.core.config import ScanConfig, Settings, load_settings


class TestLoadSettings:
    """Tests for load_settings function."""

    def test_defaults_when_no_file(self, tmp_path: Path) -> None:
        settings = load_settings(config_path=tmp_path / "nonexistent.toml")
        assert settings.scan.risk_threshold == 70.0
        assert settings.scan.trivy_timeout == 300
        assert settings.cache.ttl_hours == 24

    def test_loads_from_toml(self, tmp_path: Path) -> None:
        config = tmp_path / "flaw.toml"
        config.write_text(
            "[scan]\nrisk_threshold = 85.0\ntrivy_timeout = 120\n\n[cache]\nttl_hours = 12\n"
        )

        settings = load_settings(config_path=config)
        assert settings.scan.risk_threshold == 85.0
        assert settings.scan.trivy_timeout == 120
        assert settings.cache.ttl_hours == 12

    def test_env_vars_override_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = tmp_path / "flaw.toml"
        config.write_text("[scan]\nrisk_threshold = 50.0\n")

        monkeypatch.setenv("FLAW_RISK_THRESHOLD", "99.0")

        settings = load_settings(config_path=config)
        assert settings.scan.risk_threshold == 99.0

    def test_partial_toml(self, tmp_path: Path) -> None:
        config = tmp_path / "flaw.toml"
        config.write_text("[cache]\nttl_hours = 6\n")

        settings = load_settings(config_path=config)
        assert settings.scan.risk_threshold == 70.0
        assert settings.cache.ttl_hours == 6

    def test_settings_are_immutable(self) -> None:
        settings = Settings()
        with pytest.raises(AttributeError, match="cannot assign"):
            settings.scan = ScanConfig(risk_threshold=0.0)  # type: ignore[misc]
