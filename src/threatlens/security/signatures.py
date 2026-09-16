"""Authenticode signature verification via ``WinVerifyTrust``.

What Windows API is used?
    ``wintrust.dll!WinVerifyTrust`` with the ``WINTRUST_ACTION_GENERIC_VERIFY_V2`` policy — the
    same check Explorer and SmartScreen use. For files without an embedded signature we look the
    file hash up in the system catalog database (``CryptCATAdmin*`` APIs) and verify the catalog.

Why catalog lookup matters
    Most in-box Windows binaries (``notepad.exe``, ``kernel32.dll``…) carry **no embedded
    signature**; they are signed via ``.cat`` files under ``System32\\CatRoot``. A checker that
    skips catalogs reports half of Windows as "unsigned" — a false-positive factory.

Permissions
    None beyond read access to the file. Catalog lookup needs the *Cryptographic Services*
    (``CryptSvc``) service running; if it is not, the result is ``UNKNOWN``, not ``UNSIGNED``.

Limitations
    * Revocation is **not** checked (``WTD_REVOKE_NONE`` + cache-only URL retrieval) so that
      verification never touches the network. A revoked certificate can therefore read VALID.
    * ``VALID`` means "chains to a root trusted by this machine". It says nothing about intent:
      signed malware exists, and so does unsigned legitimate software.
    * The signer name is taken from the leaf certificate's simple display name and is only
      reported for ``VALID`` results.

Failure behaviour
    Any unexpected API failure yields ``SignatureStatus.UNKNOWN`` with ``detail`` explaining why.
    Verification never raises for per-file problems.

Alternatives
    PowerShell ``Get-AuthenticodeSignature`` (spawns a process per call — slow), Sysinternals
    ``sigcheck`` (external binary), or pywin32 (does not wrap WinVerifyTrust).
"""

from __future__ import annotations

import ctypes
import logging
import msvcrt
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Final

from threatlens.core.models import SignatureInfo, SignatureSource, SignatureStatus
from threatlens.security.hashing import (
    FileFingerprint,
    NotARegularFileError,
    fingerprint,
    normalize_path,
)
from threatlens.utils.lru import BoundedLRUCache

logger = logging.getLogger(__name__)

# WinTrust constants (wintrust.h)
WTD_UI_NONE: Final = 2
WTD_REVOKE_NONE: Final = 0
WTD_CHOICE_FILE: Final = 1
WTD_CHOICE_CATALOG: Final = 2
WTD_STATEACTION_VERIFY: Final = 1
WTD_STATEACTION_CLOSE: Final = 2
WTD_REVOCATION_CHECK_NONE: Final = 0x00000010
WTD_CACHE_ONLY_URL_RETRIEVAL: Final = 0x00001000
WTD_DISABLE_MD2_MD4: Final = 0x00002000
CERT_NAME_SIMPLE_DISPLAY_TYPE: Final = 4
MAX_PATH: Final = 260

# HRESULTs (winerror.h), as unsigned 32-bit values
TRUST_E_PROVIDER_UNKNOWN: Final = 0x800B0001
TRUST_E_SUBJECT_FORM_UNKNOWN: Final = 0x800B0003
TRUST_E_SUBJECT_NOT_TRUSTED: Final = 0x800B0004
TRUST_E_NOSIGNATURE: Final = 0x800B0100
CERT_E_EXPIRED: Final = 0x800B0101
CERT_E_REVOKED: Final = 0x800B010C
CERT_E_UNTRUSTEDROOT: Final = 0x800B0109
CERT_E_CHAINING: Final = 0x800B010A
TRUST_E_EXPLICIT_DISTRUST: Final = 0x800B0111
TRUST_E_BAD_DIGEST: Final = 0x80096010
TRUST_E_CERT_SIGNATURE: Final = 0x80096004
CRYPT_E_FILE_ERROR: Final = 0x80092003
CRYPT_E_SECURITY_SETTINGS: Final = 0x80092026

_NO_SIGNATURE_CODES: Final = frozenset(
    {TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN}
)
_UNKNOWN_CODES: Final = frozenset({CRYPT_E_FILE_ERROR, CRYPT_E_SECURITY_SETTINGS})
_INVALID_DETAILS: Final[dict[int, str]] = {
    TRUST_E_BAD_DIGEST: "file content does not match its signature (modified after signing)",
    TRUST_E_CERT_SIGNATURE: "certificate signature is invalid",
    CERT_E_UNTRUSTEDROOT: "certificate chain ends in an untrusted root",
    CERT_E_CHAINING: "certificate chain could not be built",
    CERT_E_EXPIRED: "certificate expired and signature was not timestamped",
    CERT_E_REVOKED: "certificate was revoked",
    TRUST_E_EXPLICIT_DISTRUST: "certificate is explicitly distrusted on this machine",
    TRUST_E_SUBJECT_NOT_TRUSTED: "subject is not trusted by the verification policy",
}


def classify_trust_result(hresult: int) -> tuple[SignatureStatus, str | None]:
    """Map a ``WinVerifyTrust`` HRESULT to a status. Pure function; unit-tested."""
    code = hresult & 0xFFFFFFFF
    if code == 0:
        return SignatureStatus.VALID, None
    if code in _NO_SIGNATURE_CODES:
        return SignatureStatus.UNSIGNED, "no signature present"
    if code in _UNKNOWN_CODES:
        return SignatureStatus.UNKNOWN, f"verification could not be completed (0x{code:08X})"
    detail = _INVALID_DETAILS.get(code, f"signature present but not trusted (0x{code:08X})")
    return SignatureStatus.INVALID, detail


class _GUID(ctypes.Structure):
    _fields_ = (
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    )


class _WintrustFileInfo(ctypes.Structure):
    _fields_ = (
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(_GUID)),
    )


class _WintrustCatalogInfo(ctypes.Structure):
    _fields_ = (
        ("cbStruct", wintypes.DWORD),
        ("dwCatalogVersion", wintypes.DWORD),
        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR),
        ("pcwszMemberFilePath", wintypes.LPCWSTR),
        ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", wintypes.DWORD),
        ("pcCatalogContext", wintypes.LPVOID),
        ("hCatAdmin", wintypes.HANDLE),
    )


class _WintrustUnion(ctypes.Union):
    _fields_ = (
        ("pFile", ctypes.POINTER(_WintrustFileInfo)),
        ("pCatalog", ctypes.POINTER(_WintrustCatalogInfo)),
    )


class _WintrustData(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = (
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", wintypes.LPVOID),
        ("pSIPClientData", wintypes.LPVOID),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("u", _WintrustUnion),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", wintypes.LPVOID),
    )


class _CryptProviderCert(ctypes.Structure):
    # Only the leading fields we read; instances are never allocated by us.
    _fields_ = (("cbStruct", wintypes.DWORD), ("pCert", wintypes.LPVOID))


class _CryptProviderSigner(ctypes.Structure):
    _fields_ = (
        ("cbStruct", wintypes.DWORD),
        ("sftVerifyAsOf", wintypes.FILETIME),
        ("csCertChain", wintypes.DWORD),
        ("pasCertChain", ctypes.POINTER(_CryptProviderCert)),
    )


class _CatalogInfo(ctypes.Structure):
    _fields_ = (("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * MAX_PATH))


_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

if sys.platform == "win32":
    _wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)

    _WinVerifyTrust = _wintrust.WinVerifyTrust
    _WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID), ctypes.POINTER(_WintrustData)]
    _WinVerifyTrust.restype = wintypes.LONG

    _WTHelperProvDataFromStateData = _wintrust.WTHelperProvDataFromStateData
    _WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
    _WTHelperProvDataFromStateData.restype = wintypes.LPVOID

    _WTHelperGetProvSignerFromChain = _wintrust.WTHelperGetProvSignerFromChain
    _WTHelperGetProvSignerFromChain.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    _WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(_CryptProviderSigner)

    _CryptCATAdminAcquireContext2 = _wintrust.CryptCATAdminAcquireContext2
    _CryptCATAdminAcquireContext2.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(_GUID),
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _CryptCATAdminAcquireContext2.restype = wintypes.BOOL

    _CryptCATAdminCalcHashFromFileHandle2 = _wintrust.CryptCATAdminCalcHashFromFileHandle2
    _CryptCATAdminCalcHashFromFileHandle2.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
    ]
    _CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL

    _CryptCATAdminEnumCatalogFromHash = _wintrust.CryptCATAdminEnumCatalogFromHash
    _CryptCATAdminEnumCatalogFromHash.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE

    _CryptCATCatalogInfoFromContext = _wintrust.CryptCATCatalogInfoFromContext
    _CryptCATCatalogInfoFromContext.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_CatalogInfo),
        wintypes.DWORD,
    ]
    _CryptCATCatalogInfoFromContext.restype = wintypes.BOOL

    _CryptCATAdminReleaseCatalogContext = _wintrust.CryptCATAdminReleaseCatalogContext
    _CryptCATAdminReleaseCatalogContext.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.DWORD,
    ]
    _CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL

    _CryptCATAdminReleaseContext = _wintrust.CryptCATAdminReleaseContext
    _CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _CryptCATAdminReleaseContext.restype = wintypes.BOOL

    _CertGetNameStringW = _crypt32.CertGetNameStringW
    _CertGetNameStringW.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    _CertGetNameStringW.restype = wintypes.DWORD


def _signer_from_state(state: int) -> str | None:
    """Read the leaf signer's display name from WinVerifyTrust state data."""
    provider_data = _WTHelperProvDataFromStateData(state)
    if not provider_data:
        return None
    signer = _WTHelperGetProvSignerFromChain(provider_data, 0, False, 0)
    if not signer or signer.contents.csCertChain == 0:
        return None
    cert = signer.contents.pasCertChain[0].pCert
    if not cert:
        return None
    buffer = ctypes.create_unicode_buffer(256)
    written = _CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buffer, len(buffer))
    return buffer.value if written > 1 else None


def _run_winverifytrust(data: _WintrustData) -> tuple[int, str | None]:
    """Verify, read the signer on success, and always release the provider state."""
    data.cbStruct = ctypes.sizeof(_WintrustData)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = (
        WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4
    )
    action = _WINTRUST_ACTION_GENERIC_VERIFY_V2
    hresult = int(_WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data)))
    signer: str | None = None
    try:
        if hresult == 0 and data.hWVTStateData:
            signer = _signer_from_state(data.hWVTStateData)
    finally:
        data.dwStateAction = WTD_STATEACTION_CLOSE
        _WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    return hresult & 0xFFFFFFFF, signer


def _verify_embedded(path: str, file_handle: int) -> SignatureInfo:
    file_info = _WintrustFileInfo(
        cbStruct=ctypes.sizeof(_WintrustFileInfo),
        pcwszFilePath=path,
        hFile=file_handle,
        pgKnownSubject=None,
    )
    data = _WintrustData(dwUnionChoice=WTD_CHOICE_FILE)
    data.pFile = ctypes.pointer(file_info)
    code, signer = _run_winverifytrust(data)
    status, detail = classify_trust_result(code)
    return SignatureInfo(
        status=status,
        source=SignatureSource.EMBEDDED
        if status is not SignatureStatus.UNSIGNED
        else SignatureSource.NONE,
        signer=signer if status is SignatureStatus.VALID else None,
        error_code=code or None,
        detail=detail,
    )


def _verify_catalog(path: str, file_handle: int, algorithm: str) -> SignatureInfo | None:
    """Return a catalog verification result, or ``None`` if no catalog lists the file."""
    admin = wintypes.HANDLE()
    if not _CryptCATAdminAcquireContext2(ctypes.byref(admin), None, algorithm, None, 0):
        logger.debug(
            "CryptCATAdminAcquireContext2(%s) failed: %s", algorithm, ctypes.get_last_error()
        )
        return None
    try:
        size = wintypes.DWORD(0)
        _CryptCATAdminCalcHashFromFileHandle2(admin, file_handle, ctypes.byref(size), None, 0)
        if size.value == 0:
            return None
        digest = (ctypes.c_ubyte * size.value)()
        if not _CryptCATAdminCalcHashFromFileHandle2(
            admin, file_handle, ctypes.byref(size), digest, 0
        ):
            return None

        catalog = _CryptCATAdminEnumCatalogFromHash(admin, digest, size.value, 0, None)
        if not catalog:
            return None
        try:
            info = _CatalogInfo(cbStruct=ctypes.sizeof(_CatalogInfo))
            if not _CryptCATCatalogInfoFromContext(catalog, ctypes.byref(info), 0):
                return None
            member_tag = bytes(digest).hex().upper()
            catalog_info = _WintrustCatalogInfo(
                cbStruct=ctypes.sizeof(_WintrustCatalogInfo),
                pcwszCatalogFilePath=info.wszCatalogFile,
                pcwszMemberTag=member_tag,
                pcwszMemberFilePath=path,
                hMemberFile=file_handle,
                pbCalculatedFileHash=ctypes.cast(digest, ctypes.POINTER(ctypes.c_ubyte)),
                cbCalculatedFileHash=size.value,
                hCatAdmin=admin,
            )
            data = _WintrustData(dwUnionChoice=WTD_CHOICE_CATALOG)
            data.pCatalog = ctypes.pointer(catalog_info)
            code, signer = _run_winverifytrust(data)
        finally:
            _CryptCATAdminReleaseCatalogContext(admin, catalog, 0)
    finally:
        _CryptCATAdminReleaseContext(admin, 0)

    status, detail = classify_trust_result(code)
    return SignatureInfo(
        status=status,
        source=SignatureSource.CATALOG,
        signer=signer if status is SignatureStatus.VALID else None,
        error_code=code or None,
        detail=detail,
    )


APPX_SIGNATURE_FILE: Final = "AppxSignature.p7x"
PACKAGE_DETAIL: Final = (
    "MSIX/AppX packaged app: the signature covers the package (AppxSignature.p7x), not "
    "individual files. ThreatLens does not verify package signatures; the install location "
    "is protected by Windows."
)


def system_package_roots() -> tuple[str, ...]:
    """Directories where Windows installs packaged apps. Writable only by TrustedInstaller."""
    # os.environ is case-insensitive on Windows. PROGRAMW6432 is the 64-bit Program Files even
    # when queried from a 32-bit interpreter.
    program_files = (
        os.environ.get("PROGRAMW6432") or os.environ.get("PROGRAMFILES") or r"C:\Program Files"
    )
    system_root = os.environ.get("SYSTEMROOT") or r"C:\Windows"
    return (
        normalize_path(Path(program_files) / "WindowsApps"),
        normalize_path(Path(system_root) / "SystemApps"),
    )


def packaged_app_root(path: str, roots: tuple[str, ...]) -> str | None:
    """Return the package directory if ``path`` lies inside a *system* package root.

    Only protected roots count. Accepting any directory containing ``AppxSignature.p7x`` would
    let an attacker drop that file beside an unsigned binary in a user-writable folder to turn
    UNSIGNED into UNKNOWN.
    """
    normalized = normalize_path(path)
    for root in roots:
        prefix = root.rstrip("\\/") + os.sep
        if normalized.startswith(prefix):
            package = normalized[len(prefix) :].split(os.sep, 1)[0]
            if package:
                return prefix + package
    return None


class SignatureVerifier:
    """Verify Authenticode signatures with a fingerprint-validated cache."""

    # Windows 10+ catalogs use SHA256; older third-party catalogs may still be SHA1.
    _CATALOG_ALGORITHMS: Final = ("SHA256", "SHA1")

    def __init__(
        self, cache_entries: int = 4096, package_roots: tuple[str, ...] | None = None
    ) -> None:
        self._cache: BoundedLRUCache[FileFingerprint, SignatureInfo] = BoundedLRUCache(
            cache_entries
        )
        self._package_roots = package_roots if package_roots is not None else system_package_roots()

    def verify(self, path: str) -> SignatureInfo:
        if sys.platform != "win32":
            return SignatureInfo(status=SignatureStatus.UNKNOWN, detail="requires Windows")
        try:
            key = fingerprint(path)
        except (OSError, NotARegularFileError) as exc:
            return SignatureInfo(status=SignatureStatus.UNKNOWN, detail=f"cannot read file: {exc}")

        cached = self._cache.get(key)
        if cached is not None:
            return cached

        try:
            result = self._verify_uncached(key.path)
        except OSError as exc:
            return SignatureInfo(status=SignatureStatus.UNKNOWN, detail=f"cannot read file: {exc}")
        self._cache.put(key, result)
        return result

    def _verify_uncached(self, path: str) -> SignatureInfo:
        # Open once and pass the same handle to every check so the file cannot be swapped
        # between the embedded and the catalog verification.
        with Path(path).open("rb") as handle:
            file_handle = msvcrt.get_osfhandle(handle.fileno())
            embedded = _verify_embedded(path, file_handle)
            if embedded.status is not SignatureStatus.UNSIGNED:
                return embedded
            for algorithm in self._CATALOG_ALGORITHMS:
                catalog = _verify_catalog(path, file_handle, algorithm)
                if catalog is not None:
                    return catalog

        package = packaged_app_root(path, self._package_roots)
        if package is not None and (Path(package) / APPX_SIGNATURE_FILE).is_file():
            return SignatureInfo(
                status=SignatureStatus.UNKNOWN,
                source=SignatureSource.PACKAGE,
                detail=PACKAGE_DETAIL,
            )
        return embedded
