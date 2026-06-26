#!/usr/bin/env python3
"""
Static render-bug checker — flags invalid keyword arguments passed to Dash / dbc / dcc / html
components BEFORE they blow up at render time on the Pi.

This catches the exact class of bug that broke Remote Access:
  dbc.Spinner(className="me-2")  ->  TypeError (Spinner has no `className` in dbc 2.0.4)

How it works: it AST-parses every dashboard .py file, finds each `dbc.X(...)`, `dcc.X(...)`,
and `html.X(...)` call, looks up that component's REAL allowed property names, and reports any
keyword that isn't allowed. No rendering, no Pi, no rebuild needed.

Limitations: it checks component KEYWORDS only (the main render-crash cause). It does not
validate nested Plotly figure dicts (e.g. colorbar `titleside`) — keep the static grep guards in
tests/test_asset_build.py for those.

Usage:
  python scripts/check_component_props.py            # scans dashboard/
  python scripts/check_component_props.py path ...   # scan specific files/dirs
Exit code 1 if any offender is found (so it can gate CI / a pre-build check).
"""
from __future__ import annotations

import ast
import sys
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import dash_bootstrap_components as dbc  # noqa: E402
from dash import dcc, html  # noqa: E402

_MODULES = {"dbc": dbc, "dcc": dcc, "html": html}


@lru_cache(maxsize=None)
def _allowed_props(module_name: str, comp_name: str):
    """The set of property names a component accepts, read from a bare instance.
    Returns None when we can't introspect it (then we skip — no false positives)."""
    mod = _MODULES.get(module_name)
    cls = getattr(mod, comp_name, None)
    if cls is None:
        return None
    try:
        inst = cls()                       # children/props are all optional for Dash comps
        names = getattr(inst, "_prop_names", None)
        return set(names) if names else None
    except Exception:
        return None


def scan_file(path: Path) -> list[str]:
    offenders = []
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except SyntaxError:
        return offenders

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        func = node.func
        if not isinstance(func.value, ast.Name) or func.value.id not in _MODULES:
            continue
        # Skip calls that splat **kwargs — we can't know those names statically.
        if any(kw.arg is None for kw in node.keywords):
            continue
        allowed = _allowed_props(func.value.id, func.attr)
        if allowed is None:
            continue
        for kw in node.keywords:
            if kw.arg not in allowed:
                offenders.append(
                    f"{path.relative_to(REPO)}:{kw.value.lineno}: "
                    f"{func.value.id}.{func.attr}(...) has no '{kw.arg}' "
                    f"(allowed e.g.: {', '.join(sorted(allowed)[:8])} …)")
    return offenders


def main(argv: list[str]) -> int:
    targets = [Path(a) for a in argv] or [REPO / "dashboard"]
    files: list[Path] = []
    for t in targets:
        t = t if t.is_absolute() else REPO / t
        files.extend(sorted(t.rglob("*.py")) if t.is_dir() else [t])

    offenders = [o for f in files for o in scan_file(f)]
    if offenders:
        print(f"Found {len(offenders)} invalid component keyword(s):\n")
        for o in offenders:
            print("  " + o)
        print("\nThese will raise TypeError when the component renders on the Pi.")
        return 1
    print(f"OK — no invalid dbc/dcc/html component keywords in {len(files)} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
