"""Core scanning/decision logic.

The module contains scoring rules and request normalization utilities.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Any


class WfErr(Exception):
    """Base exception for waflite."""


class CfgErr(WfErr):
    """Raised when config/rules are invalid."""


@dataclass(frozen=True)
class Rl:
    """Single detection rule.

    Args:
        rid: Rule identifier.
        rtp: Rule type (e.g. "re", "sub").
        w: Rule weight (score add).
        ps: Patterns (regexes or substrings depending on type).
        fld: Field name in request dict to inspect.
    """

    rid: str
    rtp: str
    w: int
    ps: tuple[str, ...]
    fld: str = "req"


def nrq(d: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize request dict.

    Args:
        d: Request mapping (may be partial).

    Returns:
        New dict with stable keys: ip, req, ua, st.
    """
    return {
        "ip": str(d.get("ip", "")),
        "req": str(d.get("req", "")),
        "ua": str(d.get("ua", "")),
        "st": int(d.get("st", 0)) if str(d.get("st", "")).isdigit() else 0,
    }


def mtch(rl: Rl, rq: Mapping[str, Any]) -> bool:
    """Check if rule matches request.

    Args:
        rl: Rule.
        rq: Normalized request mapping.

    Returns:
        True if matched, else False.

    Raises:
        CfgErr: If rule has unsupported type.
    """
    v = str(rq.get(rl.fld, ""))
    if rl.rtp == "sub":
        lv = v.lower()
        return any(p.lower() in lv for p in rl.ps)
    if rl.rtp == "re":
        import re

        for p in rl.ps:
            if re.search(p, v, flags=re.IGNORECASE):
                return True
        return False
    raise CfgErr(f"bad rtp: {rl.rtp!r} for {rl.rid!r}")


def scr(rls: Iterable[Rl], rq: Mapping[str, Any]) -> tuple[int, list[str]]:
    """Compute total score and matched rule ids.

    Args:
        rls: Iterable of rules.
        rq: Normalized request mapping.

    Returns:
        (score, matched_rule_ids)
    """
    s = 0
    ms: list[str] = []
    for r in rls:
        if mtch(r, rq):
            s += int(r.w)
            ms.append(r.rid)
    return s, ms


def dec(s: int, thr: int) -> str:
    """Decision from score.

    Args:
        s: Score.
        thr: Threshold.

    Returns:
        "block" if s >= thr else "allow".
    """
    return "block" if int(s) >= int(thr) else "allow"
