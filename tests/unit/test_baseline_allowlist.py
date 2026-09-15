from __future__ import annotations

from fixtures.detection import owned, proc
from fixtures.fakes import minutes
from winsentinel.core.models import (
    Attribution,
    ConnectionState,
    CorrelatedConnection,
    Direction,
    PersistenceItem,
    PersistenceKind,
    PersistenceSnapshot,
    SignatureInfo,
    SignatureSource,
    SignatureStatus,
)
from winsentinel.detection.allowlist import AllowlistEntry, AllowlistMatcher, AllowlistMatchType
from winsentinel.detection.baseline import (
    BaselineItemKind,
    capture_baseline,
    compare_baseline,
    diffs_by_kind,
)


def listener(
    pid: int, port: int, address: str = "0.0.0.0", name: str = "srv.exe"
) -> CorrelatedConnection:
    conn = owned(
        proc(pid, name),
        None,
        None,
        local=address,
        local_port=port,
        state=ConnectionState.LISTEN,
        direction=Direction.LISTENING,
    )
    return CorrelatedConnection(
        connection=conn.connection,
        attribution=Attribution.ATTRIBUTED,
        process_key=conn.process_key,
        process_name=name,
    )


def persistence(*names: str) -> PersistenceSnapshot:
    items = tuple(
        PersistenceItem(
            kind=PersistenceKind.REGISTRY_RUN,
            location=r"HKCU\Run",
            name=n,
            executable=rf"C:\{n}.exe",
        )
        for n in names
    )
    return PersistenceSnapshot(timestamp=minutes(1), items=items)


class TestBaseline:
    def test_capture_dedupes_processes_by_exe(self) -> None:
        p1 = proc(100, "chrome.exe", exe=r"C:\chrome.exe")
        p2 = proc(200, "chrome.exe", exe=r"C:\chrome.exe")  # same exe, different PID
        p3 = proc(300, "tool.exe", exe=r"C:\tool.exe")
        items = capture_baseline([p1, p2, p3], [], persistence())
        processes = [i for i in items if i.kind is BaselineItemKind.PROCESS]
        assert len(processes) == 2

    def test_compare_reports_only_additions(self) -> None:
        base = capture_baseline(
            [proc(100, "chrome.exe", exe=r"C:\chrome.exe")],
            [listener(100, 8080)],
            persistence("Updater"),
        )
        current = capture_baseline(
            [
                proc(100, "chrome.exe", exe=r"C:\chrome.exe"),
                proc(200, "evil.exe", exe=r"C:\Temp\evil.exe"),
            ],
            [listener(100, 8080), listener(200, 4444, name="evil.exe")],
            persistence("Updater", "Backdoor"),
        )
        diffs = diffs_by_kind(compare_baseline(base, current))
        assert {d.attributes.get("exe") for d in diffs[BaselineItemKind.PROCESS]} == {
            r"C:\Temp\evil.exe"
        }
        assert [d.attributes["port"] for d in diffs[BaselineItemKind.LISTENER]] == [4444]
        assert any("Backdoor" in d.label for d in diffs[BaselineItemKind.PERSISTENCE])

    def test_loopback_listeners_are_not_baselined(self) -> None:
        items = capture_baseline([], [listener(100, 9000, address="127.0.0.1")], persistence())
        assert not [i for i in items if i.kind is BaselineItemKind.LISTENER]

    def test_no_changes_yields_empty(self) -> None:
        base = capture_baseline([proc(100, "a.exe", exe=r"C:\a.exe")], [], persistence())
        assert compare_baseline(base, base) == []


VALID_SIG = SignatureInfo(
    status=SignatureStatus.VALID, source=SignatureSource.EMBEDDED, signer="Contoso Ltd"
)


class TestAllowlist:
    def test_match_by_path_sha_and_signer(self) -> None:
        entries = [
            AllowlistEntry(AllowlistMatchType.EXE_PATH, r"C:\Tools\scanner.exe"),
            AllowlistEntry(AllowlistMatchType.SHA256, "ab" * 32),
            AllowlistEntry(AllowlistMatchType.SIGNER, "Contoso Ltd"),
        ]
        matcher = AllowlistMatcher(entries)
        by_path = proc(1, "scanner.exe", exe=r"C:\TOOLS\SCANNER.EXE")  # case-insensitive
        assert matcher.allows(by_path, "NET-001")
        by_sha = proc(2, "x.exe", exe=r"C:\other.exe", sha256="ab" * 32)
        assert matcher.allows(by_sha, "PROC-001")
        by_signer = proc(3, "y.exe", exe=r"C:\y.exe", signature=VALID_SIG)
        assert matcher.allows(by_signer, "SIG-001")
        assert not matcher.allows(proc(4, "z.exe", exe=r"C:\z.exe"), "PROC-001")

    def test_signer_requires_valid_signature(self) -> None:
        matcher = AllowlistMatcher([AllowlistEntry(AllowlistMatchType.SIGNER, "Contoso Ltd")])
        invalid = proc(
            1,
            "y.exe",
            exe=r"C:\y.exe",
            signature=SignatureInfo(status=SignatureStatus.INVALID, signer="Contoso Ltd"),
        )
        assert not matcher.allows(invalid, "SIG-001")

    def test_rule_scoped_entry(self) -> None:
        matcher = AllowlistMatcher(
            [AllowlistEntry(AllowlistMatchType.EXE_PATH, r"C:\a.exe", rule_ids=("NET-004",))]
        )
        p = proc(1, "a.exe", exe=r"C:\a.exe")
        assert matcher.allows(p, "NET-004")
        assert not matcher.allows(p, "PROC-001")

    def test_expired_entry_is_ignored(self) -> None:
        entry = AllowlistEntry(AllowlistMatchType.EXE_PATH, r"C:\a.exe", expires_at=minutes(1))
        matcher = AllowlistMatcher([entry], now=minutes(2))
        assert not matcher.allows(proc(1, "a.exe", exe=r"C:\a.exe"), "PROC-001")
