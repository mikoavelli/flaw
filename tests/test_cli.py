"""Integration tests for the Flaw CLI."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from flaw.cli import app
from flaw.intelligence.epss import EPSSError
from flaw.intelligence.kev import KEVError
from flaw.models import (
    DockerfileIssue,
    EnrichedVulnerability,
    ReportSummary,
    ScanReport,
)
from flaw.scanner.dockerfile import DockerfileLintError
from flaw.scanner.installer import InstallerError
from flaw.scanner.trivy import ScannerError

runner = CliRunner()


def test_version() -> None:
    """Test --version flag."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "flaw 0.3.0" in result.stdout


def test_help() -> None:
    """Test --help flag."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage: flaw" in result.stdout


class TestUpdateCommands:
    """Tests for `flaw update` commands."""

    @patch("flaw.commands.update.epss.update")
    @patch("flaw.commands.update.kev.update")
    def test_update_cache(self, mock_kev: MagicMock, mock_epss: MagicMock) -> None:
        mock_epss.return_value = 100
        mock_kev.return_value = 50

        result = runner.invoke(app, ["update", "cache"])

        assert result.exit_code == 0
        assert "Updating EPSS" in result.stderr
        assert "Updating KEV" in result.stderr
        assert "done" in result.stderr

    @patch("flaw.commands.update.ensure_model")
    def test_update_model(self, mock_ensure: MagicMock) -> None:
        mock_ensure.return_value = MagicMock(name="model.json")
        result = runner.invoke(app, ["update", "model"])
        assert result.exit_code == 0
        assert "Updating ML Model" in result.stderr
        assert "done" in result.stderr

    @patch("flaw.commands.update.ensure_trivy")
    def test_update_trivy(self, mock_ensure: MagicMock) -> None:
        mock_ensure.return_value = "/usr/local/bin/trivy-mock"
        result = runner.invoke(app, ["update", "trivy"])
        assert result.exit_code == 0
        assert "Checking Trivy Engine" in result.stderr
        assert "done" in result.stderr

    def test_update_offline_fail(self) -> None:
        result = runner.invoke(app, ["--offline", "update", "cache"])
        assert "Cannot update cache in offline mode" in result.stderr


class TestStatusCommands:
    """Tests for `flaw status` command."""

    @patch("flaw.commands.status.get_trivy_info")
    @patch("flaw.commands.status.MODEL_PATH")
    @patch("flaw.commands.status.get_entry_count")
    @patch("flaw.commands.status.get_last_update")
    @patch("flaw.commands.status.DB_PATH")
    def test_status_all_good(
        self,
        mock_db_path: MagicMock,
        mock_last: MagicMock,
        mock_count: MagicMock,
        mock_model_path: MagicMock,
        mock_trivy_info: MagicMock,
    ) -> None:
        mock_db_path.exists.return_value = True
        mock_count.return_value = 5000
        mock_last.return_value = time.time()

        mock_model_path.exists.return_value = True
        mock_model_path.stat.return_value.st_size = 1024
        mock_model_path.stat.return_value.st_mtime = time.time()

        mock_trivy_info.return_value = ("/usr/bin/trivy", "v0.49.0")

        result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "System Status" in result.stderr
        assert "Fresh" in result.stderr
        assert "Ready" in result.stderr
        assert "v0.49.0" in result.stderr

    @patch("flaw.commands.status.get_trivy_info")
    @patch("flaw.commands.status.MODEL_PATH")
    @patch("flaw.commands.status.DB_PATH")
    def test_status_missing_components(
        self,
        mock_db_path: MagicMock,
        mock_model_path: MagicMock,
        mock_trivy_info: MagicMock,
    ) -> None:
        mock_db_path.exists.return_value = False
        mock_model_path.exists.return_value = False
        mock_trivy_info.return_value = (None, "Unknown")

        result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "Missing" in result.stderr
        assert "Run `flaw update" in result.stderr


class TestCleanCommands:
    """Tests for `flaw clean` command."""

    @patch("flaw.commands.clean.DB_PATH")
    @patch("flaw.commands.clean.CACHE_DIR")
    def test_clean_cache(self, mock_cache_dir: MagicMock, mock_db_path: MagicMock) -> None:
        mock_db_path.exists.return_value = True
        mock_cache_dir.exists.return_value = True

        with (
            patch("flaw.commands.clean.get_connection"),
            patch("flaw.commands.clean.shutil.rmtree"),
        ):
            result = runner.invoke(app, ["clean", "--cache"])

        assert result.exit_code == 0
        assert "Cache databases cleared" in result.stderr
        mock_db_path.unlink.assert_called_once()

    @patch("flaw.commands.clean.MODELS_DIR")
    def test_clean_model(self, mock_models_dir: MagicMock) -> None:
        mock_models_dir.exists.return_value = True
        mock_models_dir.iterdir.return_value = [MagicMock()]

        with patch("flaw.commands.clean.shutil.rmtree") as mock_rmtree:
            result = runner.invoke(app, ["clean", "--model"])
            assert result.exit_code == 0
            assert "ML models cleared" in result.stderr
            mock_rmtree.assert_called_once()

    @patch("flaw.commands.clean.BIN_DIR")
    def test_clean_trivy(self, mock_bin_dir: MagicMock) -> None:
        mock_bin_dir.exists.return_value = True
        mock_bin_dir.iterdir.return_value = [MagicMock()]

        with patch("flaw.commands.clean.shutil.rmtree") as mock_rmtree:
            result = runner.invoke(app, ["clean", "--trivy"])
            assert result.exit_code == 0
            assert "Trivy binaries cleared" in result.stderr
            mock_rmtree.assert_called_once()

    @patch("flaw.commands.clean.DB_PATH")
    def test_clean_nothing(self, mock_db_path: MagicMock) -> None:
        mock_db_path.exists.return_value = False
        result = runner.invoke(app, ["clean"])
        assert "Nothing to clean" in result.stderr


class TestLintCommand:
    """Tests for `flaw lint` command."""

    @patch("flaw.commands.lint.lint")
    def test_lint_success(self, mock_lint: MagicMock) -> None:
        mock_lint.return_value = [
            DockerfileIssue(id="DF-001", severity="HIGH", description="Root user")
        ]

        result = runner.invoke(app, ["lint", "Dockerfile"])

        assert result.exit_code == 0
        assert "DF-001" in result.stderr
        assert "Root user" in result.stderr

    @patch("flaw.commands.lint.lint")
    def test_lint_ci_failure(self, mock_lint: MagicMock) -> None:
        mock_lint.return_value = [
            DockerfileIssue(id="DF-001", severity="HIGH", description="Root user")
        ]

        result = runner.invoke(app, ["lint", "--ci"])

        assert result.exit_code == 1
        assert "FAIL" in result.stderr

    @patch("flaw.commands.lint.lint")
    def test_lint_ci_pass_with_low_severity(self, mock_lint: MagicMock) -> None:
        """CI should pass if issues are only INFO/LOW."""
        mock_lint.return_value = [
            DockerfileIssue(id="DF-006", severity="INFO", description="No Healthcheck")
        ]

        result = runner.invoke(app, ["lint", "--ci"])

        assert result.exit_code == 0
        assert "No Healthcheck" in result.stderr

    @patch("flaw.commands.lint.lint")
    def test_lint_json_output(self, mock_lint: MagicMock) -> None:
        mock_lint.return_value = []
        result = runner.invoke(app, ["lint", "--format", "json"])
        assert result.exit_code == 0
        assert '"total_issues": 0' in result.stdout


class TestScanCommand:
    """Tests for `flaw scan` command."""

    def _get_dummy_report(self, risk: float = 50.0) -> ScanReport:
        return ScanReport(
            image="nginx:1.24",
            scan_time="2024-01-01T00:00:00Z",
            duration_seconds=1.0,
            summary=ReportSummary(max_risk_score=risk, total=1),
            vulnerabilities=[
                EnrichedVulnerability(
                    cve_id="CVE-2024-0001",
                    pkg_name="test",
                    installed_version="1.0",
                    severity="HIGH",
                    risk_score=risk,
                )
            ],
        )

    @patch("flaw.commands.scan.run_scan")
    def test_scan_basic(self, mock_run: MagicMock) -> None:
        mock_run.return_value = self._get_dummy_report()

        result = runner.invoke(app, ["scan", "nginx:1.24"])

        assert result.exit_code == 0
        assert "Flaw — nginx:1.24" in result.stderr
        assert "CVE-2024-0001" in result.stderr

    @patch("flaw.commands.scan.run_scan")
    def test_scan_threshold_fail(self, mock_run: MagicMock) -> None:
        mock_run.return_value = self._get_dummy_report(risk=90.0)

        result = runner.invoke(app, ["scan", "nginx", "--threshold", "80"])

        assert result.exit_code == 1
        assert "exceeds threshold 80" in result.stderr

    @patch("flaw.commands.scan.run_scan")
    def test_scan_json_output(self, mock_run: MagicMock) -> None:
        mock_run.return_value = self._get_dummy_report()

        result = runner.invoke(app, ["scan", "nginx", "-f", "json"])

        assert result.exit_code == 0
        assert '"image": "nginx:1.24"' in result.stdout

    @patch("flaw.commands.scan.run_scan")
    def test_scan_sarif_output(self, mock_run: MagicMock) -> None:
        mock_run.return_value = self._get_dummy_report()

        result = runner.invoke(app, ["scan", "nginx", "-f", "sarif"])

        assert result.exit_code == 0
        assert '"version": "2.1.0"' in result.stdout

    @patch("flaw.commands.scan.run_scan")
    def test_scan_with_dockerfile(self, mock_run: MagicMock) -> None:
        mock_run.return_value = self._get_dummy_report()

        result = runner.invoke(app, ["scan", "nginx", "--dockerfile", "Dockerfile"])

        assert result.exit_code == 0
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        assert str(call_kwargs["dockerfile"]) == "Dockerfile"

    @patch("flaw.commands.scan.run_scan")
    def test_scan_with_vex_flag(self, mock_run: MagicMock) -> None:
        mock_run.return_value = self._get_dummy_report()

        result = runner.invoke(app, ["scan", "nginx", "--vex", "app-vex.json"])

        assert result.exit_code == 0
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]

        vex_paths = call_kwargs["vex_paths"]
        assert len(vex_paths) == 1
        assert str(vex_paths[0]) == "app-vex.json"


class TestCacheCommands:
    """Tests for `flaw cache` commands."""

    @patch("flaw.commands.cache.epss.update")
    @patch("flaw.commands.cache.kev.update")
    @patch("flaw.commands.cache.ensure_model")
    @patch("flaw.commands.cache.ensure_trivy")
    def test_cache_update_success(
        self,
        mock_trivy: MagicMock,
        mock_model: MagicMock,
        mock_kev: MagicMock,
        mock_epss: MagicMock,
    ) -> None:
        mock_epss.return_value = 100
        mock_kev.return_value = 50
        mock_model.return_value = True

        result = runner.invoke(app, ["cache", "update"])
        assert result.exit_code == 0
        assert "done" in result.stderr

    def test_cache_update_offline(self) -> None:
        result = runner.invoke(app, ["--offline", "cache", "update"])
        assert result.exit_code == 2
        assert "Cannot update in offline mode" in result.stderr

    @patch("flaw.commands.cache.DB_PATH")
    @patch("flaw.commands.cache.get_entry_count", return_value=100)
    @patch("flaw.commands.cache.get_last_update", return_value=time.time())
    def test_cache_status_success(
        self, mock_last: MagicMock, mock_count: MagicMock, mock_db_path: MagicMock
    ) -> None:
        mock_db_path.exists.return_value = True
        mock_db_path.stat.return_value.st_size = 1024
        result = runner.invoke(app, ["cache", "status"])
        assert result.exit_code == 0
        assert "Fresh" in result.stderr

    @patch("flaw.commands.cache.DB_PATH")
    def test_cache_status_no_db(self, mock_db_path: MagicMock) -> None:
        mock_db_path.exists.return_value = False
        result = runner.invoke(app, ["cache", "status"])
        assert result.exit_code == 1
        assert "No cache database found" in result.stderr

    @patch("flaw.commands.cache.DB_PATH")
    @patch("flaw.commands.cache.clear_all")
    def test_cache_clean(self, mock_clear: MagicMock, mock_db_path: MagicMock) -> None:
        mock_db_path.exists.return_value = True
        result = runner.invoke(app, ["cache", "clean"])
        assert result.exit_code == 0
        assert "Cache cleared" in result.stderr

    def test_cache_dir(self) -> None:
        result = runner.invoke(app, ["cache", "dir"])
        assert result.exit_code == 0
        assert "flaw" in result.stdout


class TestCliErrors:
    """Tests for graceful error handling in CLI."""

    @patch("flaw.commands.scan.run_scan", side_effect=ScannerError("Trivy crashed"))
    def test_scan_scanner_error(self, mock_run: MagicMock) -> None:
        result = runner.invoke(app, ["scan", "nginx"])
        assert result.exit_code == 2
        assert "Trivy crashed" in result.stderr

    @patch("flaw.commands.scan.run_scan", side_effect=ScannerError("Trivy crashed"))
    def test_scan_scanner_error_quiet(self, mock_run: MagicMock) -> None:
        result = runner.invoke(app, ["--quiet", "scan", "nginx"])
        assert result.exit_code == 2
        assert "Trivy crashed" not in result.stderr

    @patch("flaw.commands.lint.lint", side_effect=DockerfileLintError("Bad file"))
    def test_lint_dockerfile_error(self, mock_lint: MagicMock) -> None:
        result = runner.invoke(app, ["lint", "Dockerfile"])
        assert result.exit_code == 2
        assert "Bad file" in result.stderr

    @patch("flaw.commands.update.ensure_model", return_value=None)
    def test_update_model_fail(self, mock_model: MagicMock) -> None:
        result = runner.invoke(app, ["update", "model"])
        assert result.exit_code == 0
        assert "failed" in result.stderr


class TestCliEdgeCases:
    """Tests for edge cases and exceptions across the CLI."""

    @patch("flaw.commands.cache.epss.update", side_effect=EPSSError("EPSS Error"))
    @patch("flaw.commands.cache.kev.update", side_effect=KEVError("KEV Error"))
    @patch("flaw.commands.cache.ensure_model", return_value=None)
    @patch("flaw.commands.cache.ensure_trivy", side_effect=InstallerError("Trivy Error"))
    def test_cache_update_failures(
        self,
        mock_trivy: MagicMock,
        mock_model: MagicMock,
        mock_kev: MagicMock,
        mock_epss: MagicMock,
    ) -> None:
        """Covers error branches in `flaw cache update`."""
        result = runner.invoke(app, ["cache", "update"])
        assert result.exit_code == 0
        assert "EPSS Error" in result.stderr
        assert "KEV Error" in result.stderr
        assert "Trivy Error" in result.stderr
        assert "failed" in result.stderr

    @patch("flaw.commands.update._do_update_cache")
    @patch("flaw.commands.update._do_update_model")
    @patch("flaw.commands.update._do_update_trivy")
    def test_update_all(
        self, mock_trivy: MagicMock, mock_model: MagicMock, mock_cache: MagicMock
    ) -> None:
        """Covers `flaw update all`."""
        result = runner.invoke(app, ["update", "all"])
        assert result.exit_code == 0
        assert "All components are up to date" in result.stderr

    def test_update_offline_blocks(self) -> None:
        """Covers offline blocking in `flaw update model` and `flaw update trivy`."""
        res1 = runner.invoke(app, ["--offline", "update", "model"])
        assert "Cannot update ML model in offline mode" in res1.stderr

        res2 = runner.invoke(app, ["--offline", "update", "trivy"])
        assert "Cannot update Trivy in offline mode" in res2.stderr

    @patch("flaw.commands.scan.run_scan")
    def test_scan_with_output_file(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Covers the `if output is not None:` branch in standard table format."""
        mock_run.return_value = ScanReport(image="test", scan_time="x", duration_seconds=1.0)
        out = tmp_path / "out.txt"
        result = runner.invoke(app, ["scan", "img", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    @patch("flaw.commands.lint.lint")
    def test_lint_with_output_file(self, mock_lint: MagicMock, tmp_path: Path) -> None:
        """Covers the `if output is not None:` branch in lint table format."""
        mock_lint.return_value = []
        out = tmp_path / "out.txt"
        result = runner.invoke(app, ["lint", "Dockerfile", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    @patch("flaw.commands.status.DB_PATH")
    @patch("flaw.commands.status.get_entry_count", return_value=0)
    @patch("flaw.commands.status.get_last_update", return_value=0.0)
    def test_status_empty_cache(
        self, mock_last: MagicMock, mock_count: MagicMock, mock_db: MagicMock
    ) -> None:
        """Covers empty/never updated DB in `flaw status`."""
        mock_db.exists.return_value = True
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Empty" in result.stderr
