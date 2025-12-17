"""I/O helpers and parsers for input lines.

Supports:
- nginx combined access log lines
- raw request lines
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Any

from .core import WfErr


class InpErr(WfErr):
    """Raised when input cannot be parsed."""


@dataclass(frozen=True)
class PrsRes:
    """Parsed request record.

    Args:
        ip: Client IP.
        req: Request line (e.g. "GET / HTTP/1.1").
        ua: User-Agent.
        st: Status code (0 if unknown).
    """

    ip: str
    req: str
    ua: str
    st: int = 0

    def asd(self) -> dict[str, Any]:
        """Convert to dict."""
        return {"ip": self.ip, "req": self.req, "ua": self.ua, "st": self.st}


def rdln(p: Path) -> Iterator[str]:
    """Read non-empty lines from a UTF-8 text file.

    Args:
        p: Path to input file.

    Yields:
        Stripped lines.

    Raises:
        InpErr: If file cannot be read as UTF-8.
    """
    try:
        with p.open("r", encoding="utf-8") as f:
            for ln in f:
                s = ln.rstrip("\\n")
                if s.strip():
                    yield s
    except UnicodeDecodeError as e:
        raise InpErr("file must be UTF-8") from e
    except OSError as e:
        raise InpErr(f"cannot read: {p}") from e


def prs_raw(ln: str) -> PrsRes:
    """Parse a raw request line.

    Expected formats:
    - "IP<TAB>REQ<TAB>UA"
    - "REQ" (IP/UA become empty)

    Args:
        ln: Input line.

    Returns:
        Parsed record.
    """
    ps = ln.split("\t")
    if len(ps) == 1:
        return PrsRes(ip="", req=ps[0].strip(), ua="", st=0)
    if len(ps) >= 3:
        return PrsRes(ip=ps[0].strip(), req=ps[1].strip(), ua=ps[2].strip(), st=0)
    raise InpErr("bad raw line")


def prs_ng(ln: str) -> PrsRes:
    """Parse nginx combined access log line.

    The parser is intentionally small and matches common combined format.

    Args:
        ln: Nginx access log line.

    Returns:
        Parsed record (ip, request, ua, status).

    Raises:
        InpErr: If line does not look like combined log.
    """
    import re

    m = re.match(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<req>[^"]+)"\s+(?P<st>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"$',
        ln,
    )
    if not m:
        raise InpErr("bad nginx line")
    return PrsRes(
        ip=m.group("ip"),
        req=m.group("req"),
        ua=m.group("ua"),
        st=int(m.group("st")),
    )


def prs(fmt: str, ln: str) -> PrsRes:
    """Dispatch parser by format.

    Args:
        fmt: "nginx" or "raw".
        ln: Line.

    Returns:
        Parsed record.

    Raises:
        InpErr: If format is unsupported or parsing fails.
    """
    f = (fmt or "").lower().strip()
    if f == "nginx":
        return prs_ng(ln)
    if f == "raw":
        return prs_raw(ln)
    raise InpErr(f"bad fmt: {fmt!r}")
