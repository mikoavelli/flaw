"""Tests for Dockerfile linter."""

from __future__ import annotations

from pathlib import Path

import pytest

from flaw.scanner.dockerfile import DockerfileLintError, lint


def _write_dockerfile(tmp_path: Path, content: str) -> Path:
    """Helper to write a Dockerfile and return its path."""
    p = tmp_path / "Dockerfile"
    p.write_text(content)
    return p


class TestDockerfileLint:
    """Tests for Dockerfile security rules."""

    def test_clean_dockerfile(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM python:3.12-slim\n"
            "COPY . /app\n"
            "RUN pip install flask==3.0.0\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends curl\n"
            "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
            "USER appuser\n"
            'CMD ["python", "app.py"]\n',
        )
        issues = lint(path)
        assert len(issues) == 0

    def test_no_user_directive(self, tmp_path: Path) -> None:
        path = _write_dockerfile(tmp_path, 'FROM python:3.12\nCMD ["python"]\n')
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-001" in ids

    def test_add_instead_of_copy(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM python:3.12\nADD . /app\nUSER app\nHEALTHCHECK CMD true\n",
        )
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-002" in ids

    def test_add_with_url_is_ok(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM python:3.12\n"
            "ADD https://example.com/file.tar.gz /app/\n"
            "USER app\n"
            "HEALTHCHECK CMD true\n",
        )
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-002" not in ids

    def test_latest_tag(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM python:latest\nUSER app\nHEALTHCHECK CMD true\n",
        )
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-003" in ids

    def test_no_tag_at_all(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM python\nUSER app\nHEALTHCHECK CMD true\n",
        )
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-003" in ids

    def test_apt_no_recommends(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM debian:12\n"
            "RUN apt-get update && apt-get install -y curl\n"
            "USER app\n"
            "HEALTHCHECK CMD true\n",
        )
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-004" in ids

    def test_pip_no_pin(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM python:3.12\nRUN pip install flask requests\nUSER app\nHEALTHCHECK CMD true\n",
        )
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-005" in ids

    def test_pip_with_requirements_file_is_ok(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM python:3.12\n"
            "RUN pip install -r requirements.txt\n"
            "USER app\n"
            "HEALTHCHECK CMD true\n",
        )
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-005" not in ids

    def test_no_healthcheck(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            'FROM python:3.12\nUSER app\nCMD ["python"]\n',
        )
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-006" in ids

    def test_env_secrets(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM python:3.12\nENV API_KEY=supersecret123\nUSER app\nHEALTHCHECK CMD true\n",
        )
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-007" in ids

    def test_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(DockerfileLintError, match="not found"):
            lint(tmp_path / "nonexistent")

    def test_sorted_by_severity(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            'FROM python\nRUN pip install flask\nCMD ["python"]\n',
        )
        issues = lint(path)
        severities = [i.severity for i in issues]
        expected_order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
        for i in range(len(severities) - 1):
            assert expected_order.get(severities[i], 99) <= expected_order.get(
                severities[i + 1], 99
            )

    def test_scratch_base_no_latest_warning(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM scratch\nCOPY app /app\nUSER app\nHEALTHCHECK CMD true\n",
        )
        issues = lint(path)
        ids = [i.id for i in issues]
        assert "DF-003" not in ids

    def test_read_os_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        path = _write_dockerfile(tmp_path, "FROM python")

        def mock_read_text(*args, **kwargs):
            raise OSError("Permission denied")

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        with pytest.raises(DockerfileLintError, match="Cannot read Dockerfile"):
            lint(path)


class TestDockerfileLineNumbers:
    """Tests that line numbers are correctly reported."""

    def test_add_line_number(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM python:3.12\nUSER app\nADD . /app\nHEALTHCHECK CMD true\n",
        )
        issues = lint(path)
        add_issues = [i for i in issues if i.id == "DF-002"]
        assert len(add_issues) == 1
        assert add_issues[0].line == 3

    def test_env_secret_line_number(self, tmp_path: Path) -> None:
        path = _write_dockerfile(
            tmp_path,
            "FROM python:3.12\nUSER app\nHEALTHCHECK CMD true\nENV PASSWORD=hunter2\n",
        )
        issues = lint(path)
        env_issues = [i for i in issues if i.id == "DF-007"]
        assert len(env_issues) == 1
        assert env_issues[0].line == 4
