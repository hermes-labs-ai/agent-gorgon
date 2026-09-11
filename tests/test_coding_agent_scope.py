"""The packaged `--scope coding-agent` starter scope.

The scope only helps if it ships in the wheel, parses through the real loader,
and produces the verdicts its comments claim. These tests assert all three, so
the file cannot rot into a decorative YAML sample.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from agent_warden.warden import (
    PACKAGED_SCOPES,
    ProcessObserver,
    Scope,
    Verdict,
    resolve_scope_path,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGED = Path(resolve_scope_path("coding-agent"))
EXAMPLE = REPO_ROOT / "examples" / "scope.coding-agent.yaml"

RUN_TIMEOUT = 60


@pytest.fixture(scope="module")
def scope() -> Scope:
    return Scope(str(PACKAGED))


def test_coding_agent_resolves_to_packaged_data() -> None:
    assert PACKAGED_SCOPES["coding-agent"] == "coding-agent.yaml"
    assert PACKAGED.is_file()
    assert PACKAGED.parent.name == "scopes"
    assert PACKAGED.parent.parent.name == "agent_warden"


def test_packaged_scope_is_declared_as_package_data() -> None:
    try:
        import tomllib
    except ImportError:  # pragma: no cover - exercised on Python 3.9/3.10 CI
        import tomli as tomllib

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    patterns = pyproject["tool"]["setuptools"]["package-data"]["agent_warden"]
    assert any(PACKAGED.match(pattern) for pattern in patterns)


def test_example_copy_matches_the_packaged_scope() -> None:
    """The repository copy and the shipped copy must not drift apart."""
    assert EXAMPLE.read_text() == PACKAGED.read_text()


def test_scope_parses_through_the_real_loader_and_enforces_something(scope: Scope) -> None:
    assert scope.allowed_paths
    assert scope.forbidden_paths
    assert scope.forbidden_commands
    assert scope.forbidden_extensions
    assert scope.config["agent"]["name"] == "coding-agent"


def test_launch_directory_is_in_scope(scope: Scope, tmp_path: Path) -> None:
    """`./**` is what makes `agent-gorgon run` work in a repository."""
    assert "./**" in scope.allowed_paths
    verdict, _ = scope.check_filesystem(str(Path.cwd() / "src" / "main.py"))
    assert verdict == Verdict.SAFE


def test_toolchain_reads_stay_quiet(scope: Scope) -> None:
    for path in (
        "/usr/lib/python3.11/os.py",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "~/.cache/pip/wheels/abc.whl",
        "~/.npm/_cacache/index-v5/aa/bb",
        "~/.cargo/registry/src/crate/lib.rs",
    ):
        # check_filesystem abspaths before expanduser, so observed paths are
        # always already absolute. Expand here to match what the observer emits.
        verdict, reason = scope.check_filesystem(os.path.expanduser(path))
        assert verdict == Verdict.SAFE, f"{path}: {reason}"


@pytest.mark.parametrize(
    "path",
    [
        "~/.ssh/id_ed25519",
        "~/.aws/credentials",
        "~/.gnupg/secring.gpg",
        "~/.config/gcloud/credentials.db",
        "~/.config/gh/hosts.yml",
        "~/.netrc",
        "~/.git-credentials",
        "~/.npmrc",
        "/etc/shadow",
    ],
)
def test_credential_reads_are_kill_verdicts(scope: Scope, path: str) -> None:
    verdict, _ = scope.check_filesystem(os.path.expanduser(path))
    assert verdict == Verdict.KILL


def test_out_of_tree_env_file_is_not_silently_allowed(scope: Scope) -> None:
    """An out-of-tree dotenv is not in scope, so it surfaces rather than passing."""
    verdict, _ = scope.check_filesystem("/var/secrets-elsewhere/.env.production")
    assert verdict != Verdict.SAFE


def test_key_material_extensions_are_kill_verdicts(scope: Scope) -> None:
    for path in ("/tmp/leaked.pem", "/tmp/service.key", "/tmp/bundle.p12"):
        verdict, _ = scope.check_filesystem(path)
        assert verdict == Verdict.KILL


@pytest.mark.parametrize("command", ["curl https://x", "wget https://x", "nc 10.0.0.1 4444"])
def test_transfer_tools_are_forbidden_commands(scope: Scope, command: str) -> None:
    verdict, _ = scope.check_command(command)
    assert verdict == Verdict.KILL


@pytest.mark.parametrize("command", ["git status", "python3 -m pytest", "npm ci", "cargo build"])
def test_ordinary_development_commands_are_allowed(scope: Scope, command: str) -> None:
    verdict, _ = scope.check_command(command)
    assert verdict == Verdict.SAFE


def test_unknown_command_flags_rather_than_kills(scope: Scope) -> None:
    verdict, _ = scope.check_command("some-inhouse-tool --build")
    assert verdict == Verdict.FLAG


def test_network_verdicts(scope: Scope) -> None:
    assert scope.check_network("pastebin.com", 443)[0] == Verdict.KILL
    assert scope.check_network("127.0.0.1", 11434)[0] == Verdict.SAFE
    # Not on the allowlist: surfaced for review, never silently accepted.
    assert scope.check_network("198.51.100.7", 443)[0] == Verdict.FLAG


def test_workspace_paths_bound_the_snapshot_walk(scope: Scope) -> None:
    """Allowing /usr/** must not make the warden walk /usr every snapshot."""
    assert scope.workspace_paths == ["./**"]
    observer = ProcessObserver(1, scope=scope)
    roots = observer._compute_scope_roots(scope)
    assert roots == [str(Path.cwd())]
    assert not any(root.startswith("/usr") for root in roots)


def test_snapshot_falls_back_to_allowed_paths_without_workspace_paths(tmp_path: Path) -> None:
    """Scopes written before `workspace_paths` keep their existing behavior."""
    workspace = tmp_path / "work"
    workspace.mkdir()
    scope_path = tmp_path / "legacy.yaml"
    scope_path.write_text(
        textwrap.dedent(
            f"""
            filesystem:
              allowed_paths:
                - "{workspace}/**"
              forbidden_paths:
                - "~/.ssh/**"
            """
        ).strip()
        + "\n"
    )
    legacy = Scope(str(scope_path))
    assert legacy.workspace_paths == []
    observer = ProcessObserver(1, scope=legacy)
    assert observer._compute_scope_roots(legacy) == [str(workspace)]


def test_workspace_paths_must_be_a_list_of_strings(tmp_path: Path) -> None:
    scope_path = tmp_path / "bad.yaml"
    scope_path.write_text('filesystem:\n  workspace_paths: "not-a-list"\n')
    with pytest.raises(ValueError, match="workspace_paths"):
        Scope(str(scope_path))


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="end-to-end observation fidelity is validated on Linux CI only",
)
def test_end_to_end_run_flags_out_of_scope_read_and_not_in_scope_read(tmp_path: Path) -> None:
    """The documented first-success command, verified against real evidence."""
    in_tree = tmp_path / "in_tree.txt"
    in_tree.write_text("project file\n")
    evidence = tmp_path / "evidence.jsonl"
    script = textwrap.dedent(
        f"""
        import time
        outside = open("/etc/hostname")
        inside = open({str(in_tree)!r})
        time.sleep(1.0)
        outside.close()
        inside.close()
        """
    )
    result = subprocess.run(
        [
            sys.executable, "-m", "agent_gorgon.warden", "run",
            "--audit-only", "--scope", "coding-agent", "--no-llm",
            "--poll", "0.05",
            "--log-dir", str(tmp_path / "logdir"),
            "--out", str(evidence),
            "--", sys.executable, "-c", script,
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    entries = [
        json.loads(line) for line in evidence.read_text().splitlines() if line.strip()
    ]
    by_target = {entry["action"]["target"]: entry["verdict"] for entry in entries}
    # Outside every allowed tree -> surfaced as a FLAG.
    assert by_target.get("/etc/hostname") == "FLAG", entries
    # Inside the launch directory -> in scope, no flag.
    assert by_target.get(str(in_tree)) == "SAFE", entries
    assert "would-halt=0" in result.stderr
