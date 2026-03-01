"""Integration tests for the Flaw CLI."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from flaw.cli import app
from flaw.models import (
    DockerfileIssue,
    EnrichedVulnerability,
    ReportSummary,
    ScanReport,
)

runner = CliRunner()


def test_version() -> None:
    """Test --version flag."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "flaw 0.2.0" in result.stdout


def test_help() -> None:
    """Test --help flag."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage: flaw" in result.stdout


class TestCacheCommands:
    """Tests for `flaw cache` commands."""

    @patch("flaw.commands.cache.epss.update")
    @patch("flaw.commands.cache.kev.update")
    def test_cache_update(self, mock_kev: MagicMock, mock_epss: MagicMock) -> None:
        mock_epss.return_value = 100
        mock_kev.return_value = 50

        result = runner.invoke(app, ["cache", "update"])

        assert result.exit_code == 0
        assert "Updating EPSS" in result.stderr
        assert "Updating KEV" in result.stderr
        assert "done" in result.stderr

    @patch("flaw.commands.cache.epss.update")
    @patch("flaw.commands.cache.kev.update")
    def test_cache_update_partial_failure(self, mock_kev: MagicMock, mock_epss: MagicMock) -> None:
        """Test that one failure doesn't stop the other update."""
        from flaw.intelligence.epss import EPSSError

        mock_epss.side_effect = EPSSError("Download failed")
        mock_kev.return_value = 50

        result = runner.invoke(app, ["cache", "update"])

        assert result.exit_code == 0
        assert "failed" in result.stderr
        assert "done" in result.stderr

    def test_cache_update_offline_fail(self) -> None:
        result = runner.invoke(app, ["--offline", "cache", "update"])
        assert result.exit_code == 2
        assert "Cannot update in offline mode" in result.stderr

    @patch("flaw.commands.cache.get_entry_count")
    @patch("flaw.commands.cache.get_last_update")
    @patch("flaw.commands.cache.DB_PATH")
    def test_cache_status(
        self, mock_db_path: MagicMock, mock_last: MagicMock, mock_count: MagicMock
    ) -> None:
        mock_db_path.exists.return_value = True
        mock_db_path.stat.return_value.st_size = 1024 * 1024
        mock_count.return_value = 5000
        mock_last.return_value = 1700000000.0

        result = runner.invoke(app, ["cache", "status"])

        assert result.exit_code == 0
        assert "EPSS" in result.stderr
        assert "5,000" in result.stderr
        assert "1.0 MB" in result.stderr

    @patch("flaw.commands.cache.DB_PATH")
    def test_cache_status_no_db(self, mock_db_path: MagicMock) -> None:
        mock_db_path.exists.return_value = False
        result = runner.invoke(app, ["cache", "status"])
        assert result.exit_code != 0
        assert "No cache database found" in result.stderr

    @patch("flaw.commands.cache.DB_PATH")
    def test_cache_clean(self, mock_db_path: MagicMock) -> None:
        mock_db_path.exists.return_value = True

        with patch("flaw.commands.cache.get_connection"):
            result = runner.invoke(app, ["cache", "clean"])

        assert result.exit_code == 0
        assert "Cache cleared" in result.stderr
        mock_db_path.unlink.assert_called_once()

    @patch("flaw.commands.cache.DB_PATH")
    def test_cache_clean_nothing(self, mock_db_path: MagicMock) -> None:
        mock_db_path.exists.return_value = False
        result = runner.invoke(app, ["cache", "clean"])
        assert "No cache to clear" in result.stderr


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
