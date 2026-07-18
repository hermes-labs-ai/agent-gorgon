import socket
import tempfile

import pytest

from agent_warden.warden import Scope, Verdict


SCOPE_YAML = """
filesystem:
  allowed_paths:
    - "/tmp/safe/**"
  forbidden_paths:
    - "/tmp/secret/**"
  forbidden_extensions:
    - ".pem"
network:
  allowed_domains:
    - "example.com"
  forbidden_domains:
    - "evil.com"
  allowed_ports: [443]
process:
  allowed_commands: ["python3"]
  forbidden_commands: ["curl"]
behavior:
  flag_threshold: 5
  flag_window: 300
  max_actions_per_minute: 60
"""


def _make_scope() -> Scope:
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(SCOPE_YAML)
        path = f.name
    return Scope(path)


def test_scope_filesystem_checks():
    scope = _make_scope()
    assert scope.check_filesystem("/tmp/safe/file.txt")[0] == Verdict.SAFE
    assert scope.check_filesystem("/tmp/secret/id_rsa")[0] == Verdict.KILL
    assert scope.check_filesystem("/tmp/other/key.pem")[0] == Verdict.KILL


def test_scope_command_and_network_checks():
    scope = _make_scope()
    assert scope.check_command("python3 script.py")[0] == Verdict.SAFE
    assert scope.check_command("curl https://example.com")[0] == Verdict.KILL
    assert scope.check_network("api.example.com", 443)[0] == Verdict.SAFE
    assert scope.check_network("api.evil.com", 443)[0] == Verdict.KILL


def test_observed_ip_never_uses_reverse_dns_for_allowlisting(monkeypatch):
    scope = _make_scope()

    def _unexpected_ptr_lookup(_address: str):
        raise AssertionError("raw IP policy checks must not perform reverse DNS")

    monkeypatch.setattr(socket, "gethostbyaddr", _unexpected_ptr_lookup)
    verdict, reason = scope.check_network("203.0.113.10", 443)

    assert verdict == Verdict.FLAG
    assert "203.0.113.10" in reason


def test_raw_ip_can_be_allowlisted_explicitly():
    scope = _make_scope()
    scope.allowed_domains = ["203.0.113.10"]

    assert scope.check_network("203.0.113.10", 443)[0] == Verdict.SAFE
    assert scope.check_network("2001:db8::1", 443)[0] == Verdict.FLAG


def test_scope_handles_empty_yaml():
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("")
        path = f.name

    scope = Scope(path)
    assert scope.check_filesystem("/tmp/anything")[0] == Verdict.FLAG


def test_forbidden_command_phrase_matches_precisely():
    scope = _make_scope()
    scope.forbidden_commands = ["rm -rf /"]

    assert scope.check_command("rm -rf /")[0] == Verdict.KILL
    assert scope.check_command("rm -rf /tmp")[0] == Verdict.FLAG


def test_scope_rejects_non_mapping_yaml_root():
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("- item\n- item2\n")
        path = f.name

    with pytest.raises(ValueError):
        Scope(path)
