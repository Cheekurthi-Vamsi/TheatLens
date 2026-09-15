"""Curated knowledge used by rules. Every list is documented in docs/detection-rules.md.

Names are lowercase image file names. Matching on a *name* is only ever one signal: a name is
trivially copied, which is exactly what the masquerading rule (PROC-005) looks for.
"""

from __future__ import annotations

from typing import Final

OFFICE_APPLICATIONS: Final = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "onenote.exe",
        "msaccess.exe",
        "mspub.exe",
        "visio.exe",
        "winproj.exe",
    }
)
DOCUMENT_READERS: Final = frozenset(
    {
        "acrord32.exe",
        "acrobat.exe",
        "foxitpdfreader.exe",
        "foxitreader.exe",
        "sumatrapdf.exe",
        "wordpad.exe",
    }
)
DOCUMENT_HANDLERS: Final = OFFICE_APPLICATIONS | DOCUMENT_READERS
BROWSERS: Final = frozenset(
    {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "iexplore.exe"}
)
SERVER_PROCESSES: Final = frozenset(
    {
        "w3wp.exe",
        "httpd.exe",
        "nginx.exe",
        "tomcat.exe",
        "tomcat9.exe",
        "sqlservr.exe",
        "php-cgi.exe",
    }
)

COMMAND_SHELLS: Final = frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe"})
SCRIPT_HOSTS: Final = frozenset({"wscript.exe", "cscript.exe", "mshta.exe"})
INTERPRETERS: Final = COMMAND_SHELLS | SCRIPT_HOSTS
POWERSHELL: Final = frozenset({"powershell.exe", "pwsh.exe", "powershell_ise.exe"})

# Signed Windows binaries frequently abused to proxy execution or download payloads.
LOLBINS: Final = frozenset(
    {
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msbuild.exe",
        "installutil.exe",
        "regasm.exe",
        "regsvcs.exe",
        "cmstp.exe",
        "wmic.exe",
        "forfiles.exe",
        "msiexec.exe",
    }
)


def suspicious_parent_child(parent: str, child: str) -> tuple[str, tuple[str, ...]] | None:
    """Return ``(explanation, mitre_techniques)`` if the pair is unusual, else ``None``."""
    p, c = parent.lower(), child.lower()
    if p in DOCUMENT_HANDLERS and c in INTERPRETERS | LOLBINS:
        return (
            f"Document applications such as {parent} rarely need to start {child}; this is a "
            "common pattern when a malicious document runs a macro or exploit",
            ("T1204.002", "T1059"),
        )
    if p == "wmiprvse.exe" and c in INTERPRETERS:
        return (
            "The WMI provider host starting an interpreter is a typical sign of remote or "
            "scripted WMI command execution",
            ("T1047",),
        )
    if p == "services.exe" and c in COMMAND_SHELLS:
        return (
            "A service whose binary is a command shell is how remote execution tools "
            "(PsExec-style) run commands",
            ("T1569.002",),
        )
    if p in SERVER_PROCESSES and c in INTERPRETERS:
        return (
            f"A server process ({parent}) starting {child} can indicate a web shell or command "
            "injection",
            ("T1505.003", "T1059"),
        )
    # cmd.exe is excluded for browsers: native-messaging hosts are legitimately launched via .bat.
    if p in BROWSERS and c in (POWERSHELL | SCRIPT_HOSTS):
        return (
            f"Browsers ({parent}) do not normally start {child}; this can indicate a "
            "drive-by download or a malicious extension",
            ("T1189", "T1059"),
        )
    return None


# Windows system binaries and the directories (relative to %SystemRoot%) they legitimately run from.
_SYSTEM_DIRS: Final = ("system32", "syswow64")
SYSTEM_BINARY_LOCATIONS: Final[dict[str, tuple[str, ...]]] = {
    **dict.fromkeys(
        (
            "svchost.exe",
            "lsass.exe",
            "lsaiso.exe",
            "csrss.exe",
            "smss.exe",
            "services.exe",
            "wininit.exe",
            "winlogon.exe",
            "spoolsv.exe",
            "taskhostw.exe",
            "dllhost.exe",
            "conhost.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "cmd.exe",
            "fontdrvhost.exe",
            "dwm.exe",
            "sihost.exe",
            "ctfmon.exe",
            "wuauclt.exe",
            "searchindexer.exe",
            "runtimebroker.exe",
            "taskmgr.exe",
            "certutil.exe",
        ),
        _SYSTEM_DIRS,
    ),
    "wmiprvse.exe": ("system32\\wbem", "syswow64\\wbem"),
    "explorer.exe": ("", "syswow64"),
    "powershell.exe": ("system32\\windowspowershell\\v1.0", "syswow64\\windowspowershell\\v1.0"),
}
# Component store copies are legitimate for some binaries during servicing.
ALWAYS_ALLOWED_SYSTEM_SUBDIRS: Final = ("winsxs",)

DOCUMENT_EXTENSIONS: Final = (
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "zip", "rar", "7z", "mp3", "mp4", "mov",
)  # fmt: skip
EXECUTABLE_EXTENSIONS: Final = ("exe", "scr", "com", "pif", "cmd", "bat")
