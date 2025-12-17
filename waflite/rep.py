"""Reporting utilities."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable, Mapping, Any

from .core import WfErr


class OutErr(WfErr):
    """Raised when report cannot be written."""


def wr_jsonl(p: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    """Write report as JSON Lines.

    Args:
        p: Output path.
        rows: Iterable of dict-like rows.

    Raises:
        OutErr: On write errors.
    """
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(dict(r), ensure_ascii=False) + "\n")
    except OSError as e:
        raise OutErr(f"cannot write: {p}") from e


def wr_csv(p: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    """Write report as CSV.

    Args:
        p: Output path.
        rows: Iterable of dict-like rows.

    Raises:
        OutErr: On write errors.
    """
    rows = list(rows)
    if not rows:
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    except OSError as e:
        raise OutErr(f"cannot write: {p}") from e
