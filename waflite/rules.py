"""Rules and config loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core import Rl, CfgErr


def dfl_rls() -> list[Rl]:
    """Default ruleset.

    Returns:
        List of rules with simple patterns for common web attacks.
    """
    return [
        Rl("sqli_1", "re", 5, (r"(\%27)|(\')|(\-\-)|(\%23)|(#)",), "req"),
        Rl("sqli_2", "re", 6, (r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\b",), "req"),
        Rl("xss_1", "re", 5, (r"<\s*script\b", r"onerror\s*=", r"onload\s*="), "req"),
        Rl("trav_1", "sub", 4, ("../", "..\\", "%2e%2e%2f", "%2e%2e%5c"), "req"),
        Rl(
            "cmd_1",
            "re",
            6,
            (r"[;&|`]\s*(bash|sh|cmd|powershell)\b", r"\b(wget|curl)\b\s+https?://"),
            "req",
        ),
        Rl("ua_1", "re", 3, (r"\b(sqlmap|nikto|nmap|acunetix|masscan)\b",), "ua"),
    ]


def ld_cfg(p: Path | None) -> dict[str, Any]:
    """Load config JSON.

    Args:
        p: Path to config JSON or None.

    Returns:
        Dict with keys: thr, rls, ign_ua.

    Raises:
        CfgErr: If config cannot be loaded or invalid.
    """
    if p is None:
        return {"thr": 7, "rls": [r.__dict__ for r in dfl_rls()], "ign_ua": []}
    try:
        txt = p.read_text(encoding="utf-8")
        d = json.loads(txt)
    except OSError as e:
        raise CfgErr(f"cannot read cfg: {p}") from e
    except json.JSONDecodeError as e:
        raise CfgErr("cfg must be JSON") from e
    if not isinstance(d, dict):
        raise CfgErr("cfg root must be object")
    d.setdefault("thr", 7)
    d.setdefault("ign_ua", [])
    d.setdefault("rls", [r.__dict__ for r in dfl_rls()])
    if not isinstance(d["rls"], list) or not d["rls"]:
        raise CfgErr("cfg.rls must be non-empty list")
    return d


def ld_rls(d: dict[str, Any]) -> tuple[int, list[Rl], list[str]]:
    """Build rules from loaded config.

    Args:
        d: Config dict from ld_cfg.

    Returns:
        (thr, rules, ign_ua)

    Raises:
        CfgErr: If rules are malformed.
    """
    thr = int(d.get("thr", 7))
    ign_ua = list(d.get("ign_ua", []))
    rls: list[Rl] = []
    for x in d.get("rls", []):
        if not isinstance(x, dict):
            raise CfgErr("cfg.rls items must be objects")
        try:
            rls.append(
                Rl(
                    rid=str(x["rid"]),
                    rtp=str(x["rtp"]),
                    w=int(x["w"]),
                    ps=tuple(map(str, x.get("ps", ()))),
                    fld=str(x.get("fld", "req")),
                )
            )
        except KeyError as e:
            raise CfgErr(f"missing field: {e}") from e
    if not rls:
        raise CfgErr("no rules")
    return thr, rls, ign_ua
