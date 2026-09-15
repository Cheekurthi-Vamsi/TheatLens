# Contributing

## Development setup

```powershell
py -3.12 -m venv .venv          # or -3.13
.venv\Scripts\activate
pip install -e ".[dev]"
```

## Quality gates (all must pass)

```powershell
ruff format --check src tests
ruff check src tests
mypy                             # strict mode, configured in pyproject.toml
pytest                           # unit + integration (integration needs Windows)
pytest tests/unit                # fast, platform-independent subset
```

## Engineering rules

* **Read `docs/architecture.md` first.** Respect the dependency rules in §5.3.
* **No placeholder code.** A command is registered only when it works and is tested.
* **Every Windows API you add** must be documented in its module docstring and
  `docs/windows-internals.md`: which API, why, required permissions, limitations, failure
  behaviour, alternatives.
* **Declare `argtypes` and `restype`** for every ctypes foreign function.
* **Never crash on a vanished process.** Record a `FieldIssue` and continue.
* **Untrusted text** (process names, paths, command lines, registry values) is rendered only via
  `sanitize_display` + `rich.text.Text`, and logged only via `%s` arguments.
* **No shell invocation.** No `os.system`, no `shell=True`.
* **Detection language:** "suspicious", "unusual", "requires investigation" — never "malware"
  without strong, explicit evidence.
* **Tests:** unit tests use the fakes in `tests/fixtures/fakes.py`; integration tests may only
  observe processes they spawn themselves and must not depend on internet access.
