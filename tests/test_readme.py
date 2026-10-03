"""
The README's Python examples run, in order, in one namespace.

A block preceded by a ``<!-- readme-test: skip -->`` line is a fragment that can't run on its own.
One preceded by ``<!-- readme-test: needs <module> -->`` runs only when that module is installed.
"""

import importlib.util
import os
import re
from pathlib import Path

from pydantic_cryptography import _jwk

README = Path(__file__).parent.parent / "README.md"
BLOCK = re.compile(r"(?P<before>[^\n]*)\n```python\n(?P<code>.*?)\n```", re.DOTALL)
SKIP = "<!-- readme-test: skip -->"
NEEDS = re.compile(r"<!-- readme-test: needs (?P<module>[\w.]+) -->")


def runs(before: str) -> bool:
    """Whether the block after the line `before` runs."""
    needs = NEEDS.fullmatch(before.strip())
    return before.strip() != SKIP and (not needs or bool(importlib.util.find_spec(needs["module"])))


def test_readme_examples_run() -> None:
    text = README.read_text()
    blocks = [m for m in BLOCK.finditer(text) if runs(m["before"])]
    assert len(blocks) >= 5  # the pattern still finds the examples
    # like a module: without `__name__`, Pydantic models get the module "builtins"
    namespace: dict[str, object] = {"__name__": "readme"}
    environ = dict(os.environ)  # the examples set environment variables
    try:
        for match in blocks:
            line = text.count("\n", 0, match.start("code")) + 1
            code = compile(match["code"], f"{README}:{line}", "exec")
            exec(code, namespace)
    finally:
        os.environ.clear()
        os.environ.update(environ)


def test_readme_algorithms() -> None:
    """The README's table of algorithms matches the tables in _jwk.py, the default first."""
    header = "| Key | Default `alg` | Others |\n| --- | --- | --- |\n"
    table = README.read_text().split(header)[1].split("\n\n")[0]
    rows: dict[str, tuple[str, ...]] = {}
    for line in table.splitlines():
        key, default, others = (cell.strip() for cell in line.strip("|").split("|"))
        rows[key] = (default, *(others.split(", ") if others else ()))
    ec = {f"EC {curve.crv}": curve.algs for curve in _jwk.EC_CURVES.values()}
    assert rows == dict([*_jwk.ALGS.items(), *ec.items()])
