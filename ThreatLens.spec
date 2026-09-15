# PyInstaller spec for ThreatLens.exe
#
# Build:  pyinstaller ThreatLens.spec --noconfirm
# Output: dist/ThreatLens.exe  (single-file console application)
#
# One-file, console mode. Running the exe with no arguments opens the live dashboard; any
# arguments are the normal CLI (ThreatLens.exe processes, ThreatLens.exe monitor, ...).

from PyInstaller.utils.hooks import collect_submodules

# watchdog selects its platform observer dynamically, so its submodules must be collected.
hidden_imports = [
    *collect_submodules("watchdog"),
    "winsentinel",
    "winsentinel.cli",
]

a = Analysis(
    ["packaging/threatlens_main.py"],
    pathex=["src"],
    binaries=[],
    datas=[],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "pytest", "mypy", "ruff", "IPython", "PIL", "numpy", "PyInstaller",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ThreatLens",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
