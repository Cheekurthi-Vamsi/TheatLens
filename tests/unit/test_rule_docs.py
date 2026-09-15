from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_rule_docs_are_current() -> None:
    """docs/detection-rules.md must match the rule metadata (run scripts/generate_rule_docs.py)."""
    spec = importlib.util.spec_from_file_location(
        "generate_rule_docs", ROOT / "scripts" / "generate_rule_docs.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected = module.render()
    actual = (ROOT / "docs" / "detection-rules.md").read_text(encoding="utf-8")
    assert actual == expected, (
        "docs/detection-rules.md is stale: run python scripts/generate_rule_docs.py"
    )
