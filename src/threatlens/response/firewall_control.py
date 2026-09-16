"""Windows Firewall control via ``netsh advfirewall`` (a supported management interface).

Spec §24: use the Windows Firewall APIs or a supported management interface — never packet
interception. ``netsh advfirewall firewall`` is that interface. ThreatLens:

* only ever *adds* block rules and *removes* rules it created (every rule name is prefixed
  ``ThreatLens:``), so it can never weaken the firewall or touch the user's own rules;
* blocks **outbound** by default (stopping a process phoning out is the useful case);
* records who/what/when for every change and provides an unblock for each;
* requires administrator rights — without them ``netsh`` refuses and the error is surfaced.

Subprocess is invoked with an argument list and **no shell**, so values (IPs, ports, paths) are
never interpreted by a command processor. Inputs are validated before they reach here.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Final, Protocol

from threatlens.errors import ThreatLensError
from threatlens.utils.networking import validate_ip, validate_port

RULE_PREFIX: Final = "ThreatLens:"
_NETSH: Final = "netsh"
_TIMEOUT: Final = 15.0


class FirewallError(ThreatLensError):
    """A firewall operation failed (often: not running as administrator)."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class FirewallBackend(Protocol):
    def run(self, args: list[str]) -> CommandResult: ...


class NetshBackend:
    """Runs ``netsh`` with no shell. Only ``advfirewall firewall`` subcommands are ever passed."""

    def run(self, args: list[str]) -> CommandResult:
        try:
            completed = subprocess.run(
                [_NETSH, *args],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError as exc:
            raise FirewallError("netsh not found; Windows Firewall control is unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise FirewallError("netsh timed out") from exc
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True, slots=True)
class FirewallRuleSpec:
    rule_name: str
    target_type: str  # IP | PORT | PROGRAM
    target: str
    direction: str  # out | in
    netsh_args: tuple[str, ...]


def _rule_name(kind: str, target: str) -> str:
    return f"{RULE_PREFIX}{kind}:{target}"


def block_ip_spec(ip: str, direction: str = "out") -> FirewallRuleSpec:
    address = validate_ip(ip)
    name = _rule_name("ip", address)
    return FirewallRuleSpec(
        rule_name=name,
        target_type="IP",
        target=address,
        direction=direction,
        netsh_args=(
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            f"dir={direction}",
            "action=block",
            f"remoteip={address}",
        ),
    )


def block_port_spec(port: int, protocol: str = "TCP", direction: str = "out") -> FirewallRuleSpec:
    port = validate_port(port)
    proto = protocol.upper()
    if proto not in ("TCP", "UDP"):
        raise FirewallError(f"protocol must be TCP or UDP, not {protocol!r}")
    name = _rule_name("port", f"{proto}-{port}")
    port_key = "remoteport" if direction == "out" else "localport"
    return FirewallRuleSpec(
        rule_name=name,
        target_type="PORT",
        target=f"{proto}/{port}",
        direction=direction,
        netsh_args=(
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            f"dir={direction}",
            "action=block",
            f"protocol={proto}",
            f"{port_key}={port}",
        ),
    )


def block_program_spec(path: str, direction: str = "out") -> FirewallRuleSpec:
    if "\x00" in path or "\n" in path:
        raise FirewallError("invalid program path")
    name = _rule_name("program", path)
    return FirewallRuleSpec(
        rule_name=name,
        target_type="PROGRAM",
        target=path,
        direction=direction,
        netsh_args=(
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            f"dir={direction}",
            "action=block",
            f"program={path}",
        ),
    )


class FirewallController:
    def __init__(self, backend: FirewallBackend | None = None) -> None:
        self._backend = backend or NetshBackend()

    def add(self, spec: FirewallRuleSpec) -> None:
        result = self._backend.run(list(spec.netsh_args))
        if result.returncode != 0 or "Ok." not in result.stdout:
            raise FirewallError(self._explain(result))

    def remove(self, rule_name: str) -> None:
        if not rule_name.startswith(RULE_PREFIX):
            raise FirewallError(
                f"refusing to delete a rule not created by ThreatLens: {rule_name!r}"
            )
        result = self._backend.run(
            ["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        )
        if result.returncode != 0 and "No rules match" not in result.stdout:
            raise FirewallError(self._explain(result))

    def list_rules(self) -> list[str]:
        """ThreatLens-created rule names currently present."""
        result = self._backend.run(
            ["advfirewall", "firewall", "show", "rule", f"name=all"]  # noqa: F541
        )
        names: list[str] = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("rule name:"):
                value = stripped.split(":", 1)[1].strip()
                if value.startswith(RULE_PREFIX):
                    names.append(value)
        return names

    @staticmethod
    def _explain(result: CommandResult) -> str:
        text = (result.stderr or result.stdout).strip()
        if (
            "requested operation requires elevation" in text.lower()
            or "administrator" in text.lower()
        ):
            return "administrator rights are required to change the firewall (run elevated)"
        return text or f"netsh exited with code {result.returncode}"
