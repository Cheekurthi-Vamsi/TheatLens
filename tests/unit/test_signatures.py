from __future__ import annotations

import pytest

from winsentinel.core.models import SignatureStatus
from winsentinel.security import signatures as sig


@pytest.mark.parametrize(
    ("hresult", "status"),
    [
        (0, SignatureStatus.VALID),
        (sig.TRUST_E_NOSIGNATURE, SignatureStatus.UNSIGNED),
        (sig.TRUST_E_SUBJECT_FORM_UNKNOWN, SignatureStatus.UNSIGNED),
        (sig.TRUST_E_BAD_DIGEST, SignatureStatus.INVALID),
        (sig.CERT_E_UNTRUSTEDROOT, SignatureStatus.INVALID),
        (sig.TRUST_E_EXPLICIT_DISTRUST, SignatureStatus.INVALID),
        (sig.CRYPT_E_SECURITY_SETTINGS, SignatureStatus.UNKNOWN),
        (
            0x800B9999,
            SignatureStatus.INVALID,
        ),  # unrecognised trust failure: signature present, not trusted
    ],
)
def test_classify_trust_result(hresult: int, status: SignatureStatus) -> None:
    assert sig.classify_trust_result(hresult)[0] is status


def test_classify_accepts_signed_hresult() -> None:
    signed = sig.TRUST_E_BAD_DIGEST - 2**32  # how a LONG return value arrives
    assert sig.classify_trust_result(signed)[0] is SignatureStatus.INVALID


ROOTS = (r"c:\program files\windowsapps", r"c:\windows\systemapps")


def test_packaged_app_root_inside_protected_root() -> None:
    path = r"C:\Program Files\WindowsApps\Pkg_1.0_x64__abc\App\app.exe"
    assert sig.packaged_app_root(path, ROOTS) == r"c:\program files\windowsapps\pkg_1.0_x64__abc"


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\bob\AppData\Local\Temp\WindowsApps\Pkg\evil.exe",  # look-alike in user space
        r"C:\Program Files\WindowsAppsEvil\Pkg\evil.exe",  # prefix trick
        r"C:\Program Files\WindowsApps",  # the root itself
    ],
)
def test_packaged_app_root_rejects_lookalikes(path: str) -> None:
    assert sig.packaged_app_root(path, ROOTS) is None
