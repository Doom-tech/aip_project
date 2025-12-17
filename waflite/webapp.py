"""Web app: панель правил + demo shop.

Панель:
- список правил
- добавление/удаление
- тест строки

Shop (demo):
- каталог, категории, поиск, сортировка
- карточка товара
- корзина (cookie)
- checkout + создание заказа (в памяти, на время процесса)

WAF: middleware для /shop и /api/shop.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .core import Rl, nrq, scr, dec, CfgErr


class DbErr(Exception):
    """Ошибка хранилища правил."""


def _ld_db(p: Path) -> dict[str, Any]:
    """Load rules db json.

    Args:
        p: Path to db json.

    Returns:
        Dict with keys: thr, ign_ua, rls.
    """
    if not p.exists():
        return {"thr": 7, "ign_ua": [], "rls": []}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise DbErr(f"не могу прочитать db: {p}") from e
    except json.JSONDecodeError as e:
        raise DbErr("db должен быть json") from e
    if not isinstance(d, dict):
        raise DbErr("db root должен быть object")
    d.setdefault("thr", 7)
    d.setdefault("ign_ua", [])
    d.setdefault("rls", [])
    return d


def _sv_db(p: Path, d: dict[str, Any]) -> None:
    """Save rules db json.

    Args:
        p: Path.
        d: Dict to save.
    """
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        raise DbErr(f"не могу записать db: {p}") from e


def _mk_rl(x: dict[str, Any]) -> Rl:
    """Make rule from dict."""
    try:
        return Rl(
            rid=str(x["rid"]),
            rtp=str(x["rtp"]),
            w=int(x["w"]),
            ps=tuple(map(str, x.get("ps", ()))),
            fld=str(x.get("fld", "req")),
        )
    except KeyError as e:
        raise CfgErr(f"нет поля: {e}") from e


def _idn(s: str) -> str:
    """Normalize id."""
    return "".join(ch for ch in (s or "").strip() if ch.isalnum() or ch in ("_", "-"))[:40]


def _waf_do(db: dict[str, Any], rq: dict[str, Any]) -> dict[str, Any]:
    """Run WAF scoring and decision.

    Args:
        db: db dict (thr, ign_ua, rls).
        rq: request dict (ip, req, ua, st).

    Returns:
        Result dict with scr, dec, m.
    """
    thr = int(db.get("thr", 7))
    ign = list(db.get("ign_ua", []))
    rls = [_mk_rl(x) for x in db.get("rls", [])]
    nr = nrq(rq)
    s, ms = scr(rls, nr)
    ua = nr.get("ua", "")
    if any(x.lower() in ua.lower() for x in ign):
        s = max(0, s - 3)
    return {"scr": s, "dec": dec(s, thr), "m": ms, "thr": thr}


def _itms() -> list[dict[str, Any]]:
    return [
        {
            "id": 1,
            "nm": "USB Rubber Ducky (demo)",
            "pr": 1999,
            "cat": "pentest",
            "stk": 17,
            "ds": "HID-инъекция. Учебный товар.",
            "rt": 4.7,
            "rv": 128,
        },
        {
            "id": 2,
            "nm": "YubiKey (demo)",
            "pr": 5999,
            "cat": "auth",
            "stk": 42,
            "ds": "2FA ключ. Учебный товар.",
            "rt": 4.9,
            "rv": 981,
        },
        {
            "id": 3,
            "nm": "Wi‑Fi Adapter (demo)",
            "pr": 1299,
            "cat": "net",
            "stk": 9,
            "ds": "Адаптер для лабораторных работ.",
            "rt": 4.2,
            "rv": 77,
        },
        {
            "id": 4,
            "nm": "RFID Reader (demo)",
            "pr": 2499,
            "cat": "rf",
            "stk": 6,
            "ds": "Ридер для тестового стенда.",
            "rt": 4.3,
            "rv": 54,
        },
        {
            "id": 5,
            "nm": "Cable Set (demo)",
            "pr": 499,
            "cat": "misc",
            "stk": 120,
            "ds": "Набор кабелей.",
            "rt": 4.1,
            "rv": 210,
        },
    ]


def _cats() -> list[dict[str, str]]:
    return [
        {"id": "all", "nm": "Все"},
        {"id": "auth", "nm": "Auth"},
        {"id": "net", "nm": "Network"},
        {"id": "pentest", "nm": "Pentest"},
        {"id": "rf", "nm": "RF"},
        {"id": "misc", "nm": "Misc"},
    ]


def _flt(q: str, cat: str, srt: str) -> list[dict[str, Any]]:
    its = _itms()
    q2 = (q or "").strip().lower()
    if cat and cat != "all":
        its = [x for x in its if x["cat"] == cat]
    if q2:
        its = [x for x in its if q2 in x["nm"].lower() or q2 in x["ds"].lower()]
    if srt == "pr_asc":
        its = sorted(its, key=lambda x: x["pr"])
    elif srt == "pr_desc":
        its = sorted(its, key=lambda x: -x["pr"])
    elif srt == "rt_desc":
        its = sorted(its, key=lambda x: (-float(x["rt"]), -int(x["rv"])))
    return its


def _ck_ld(req: Request) -> dict[str, int]:
    """Load cart from cookie."""
    raw = req.cookies.get("cart", "")
    if not raw:
        return {}
    try:
        d = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(d, dict):
        return {}
    out: dict[str, int] = {}
    for k, v in d.items():
        try:
            out[str(int(k))] = max(0, int(v))
        except Exception:
            continue
    return {k: v for k, v in out.items() if v > 0}


def _ck_sv(resp: RedirectResponse | HTMLResponse | JSONResponse, c: dict[str, int]) -> None:
    """Save cart to cookie."""
    resp.set_cookie("cart", json.dumps(c, ensure_ascii=False), max_age=7 * 24 * 3600, httponly=True, samesite="lax")


def _ct_sum(c: dict[str, int]) -> dict[str, Any]:
    its = {x["id"]: x for x in _itms()}
    rows: list[dict[str, Any]] = []
    ttl = 0
    cnt = 0
    for k, q in c.items():
        iid = int(k)
        it = its.get(iid)
        if not it:
            continue
        q2 = min(int(q), int(it["stk"]))
        sm = int(it["pr"]) * q2
        ttl += sm
        cnt += q2
        rows.append({"id": iid, "nm": it["nm"], "pr": it["pr"], "q": q2, "sm": sm})
    return {"rows": rows, "ttl": ttl, "cnt": cnt}


def mk_app(dbp: Path) -> FastAPI:
    """Create FastAPI app.

    Args:
        dbp: Path to rules db json.

    Returns:
        FastAPI app.
    """
    app = FastAPI(title="waflite-web")
    tpls = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "tpls"))

    ords: dict[str, dict[str, Any]] = {}

    def gdb() -> dict[str, Any]:
        return _ld_db(dbp)

    def sdb(d: dict[str, Any]) -> None:
        _sv_db(dbp, d)

    @app.middleware("http")
    async def waf_mw(req: Request, call_next):
        p = req.url.path
        if p.startswith("/shop") or p.startswith("/api/shop"):
            db = gdb()
            ip = req.client.host if req.client else ""
            ua = req.headers.get("user-agent", "")
            qs = str(req.url.query)
            line = f"{req.method} {p}{('?' + qs) if qs else ''} HTTP/1.1"
            r = _waf_do(db, {"ip": ip, "req": line, "ua": ua, "st": 0})
            if r["dec"] == "block":
                return PlainTextResponse(
                    f"blocked by waflite (scr={r['scr']}, thr={r['thr']}, m={','.join(r['m'])})",
                    status_code=403,
                )
        return await call_next(req)

    # --- UI

    @app.get("/", response_class=HTMLResponse)
    async def ui_root(req: Request):
        return RedirectResponse(url="/ui", status_code=302)

    @app.get("/ui", response_class=HTMLResponse)
    async def ui(req: Request):
        db = gdb()
        return tpls.TemplateResponse("ui.html", {"request": req, "db": db, "msg": ""})

    @app.post("/ui/thr", response_class=HTMLResponse)
    async def ui_thr(req: Request, thr: int = Form(...)):
        db = gdb()
        db["thr"] = int(thr)
        sdb(db)
        return RedirectResponse(url="/ui", status_code=303)

    @app.post("/ui/ign", response_class=HTMLResponse)
    async def ui_ign(req: Request, ign: str = Form("")):
        db = gdb()
        xs = [x.strip() for x in (ign or "").split(",") if x.strip()]
        db["ign_ua"] = xs
        sdb(db)
        return RedirectResponse(url="/ui", status_code=303)

    @app.post("/ui/rl/add", response_class=HTMLResponse)
    async def ui_add(
        req: Request,
        rid: str = Form(...),
        rtp: str = Form(...),
        wv: int = Form(...),
        fld: str = Form("req"),
        ps: str = Form(""),
    ):
        db = gdb()
        rid2 = _idn(rid)
        if not rid2:
            raise HTTPException(400, "bad rid")
        pats = [x.strip() for x in (ps or "").splitlines() if x.strip()]
        db["rls"] = [x for x in db.get("rls", []) if str(x.get("rid")) != rid2]
        db["rls"].append({"rid": rid2, "rtp": rtp, "w": int(wv), "ps": pats, "fld": fld})
        sdb(db)
        return RedirectResponse(url="/ui", status_code=303)

    @app.post("/ui/rl/del", response_class=HTMLResponse)
    async def ui_del(req: Request, rid: str = Form(...)):
        db = gdb()
        rid2 = str(rid)
        db["rls"] = [x for x in db.get("rls", []) if str(x.get("rid")) != rid2]
        sdb(db)
        return RedirectResponse(url="/ui", status_code=303)

    @app.post("/ui/tst", response_class=HTMLResponse)
    async def ui_tst(req: Request, reqln: str = Form(...), ua: str = Form("")):
        db = gdb()
        r = _waf_do(db, {"ip": "0.0.0.0", "req": reqln, "ua": ua, "st": 0})
        msg = f"scr={r['scr']} thr={r['thr']} dec={r['dec']} m={','.join(r['m'])}"
        return tpls.TemplateResponse("ui.html", {"request": req, "db": db, "msg": msg})

    # --- API rules

    @app.get("/api/rls")
    async def api_rls():
        return JSONResponse(gdb())

    @app.put("/api/rls")
    async def api_put(d: dict[str, Any]):
        if not isinstance(d, dict):
            raise HTTPException(400, "bad json")
        _sv_db(dbp, d)
        return {"ok": True}

    @app.post("/api/tst")
    async def api_tst(d: dict[str, Any]):
        db = gdb()
        r = _waf_do(
            db,
            {"ip": d.get("ip", ""), "req": d.get("req", ""), "ua": d.get("ua", ""), "st": d.get("st", 0)},
        )
        return r

    # --- API shop

    @app.get("/api/shop/items")
    async def api_items(q: str = "", cat: str = "all", srt: str = "rt_desc"):
        return {"items": _flt(q, cat, srt), "cats": _cats()}

    @app.get("/api/shop/cart")
    async def api_cart(req: Request):
        c = _ck_ld(req)
        return _ct_sum(c)

    @app.post("/api/shop/cart/add")
    async def api_cart_add(req: Request, iid: int = Form(...), q: int = Form(1)):
        c = _ck_ld(req)
        c[str(int(iid))] = int(c.get(str(int(iid)), 0)) + max(1, int(q))
        r = JSONResponse({"ok": True})
        _ck_sv(r, c)
        return r

    @app.post("/api/shop/cart/rm")
    async def api_cart_rm(req: Request, iid: int = Form(...)):
        c = _ck_ld(req)
        c.pop(str(int(iid)), None)
        r = JSONResponse({"ok": True})
        _ck_sv(r, c)
        return r

    @app.post("/api/shop/order")
    async def api_ord(req: Request, nm: str = Form(...), em: str = Form(...), ad: str = Form(...), pm: str = Form("card")):
        c = _ck_ld(req)
        sm = _ct_sum(c)
        if not sm["rows"]:
            return JSONResponse({"ok": False, "err": "empty cart"}, status_code=400)
        oid = secrets.token_hex(8)
        ords[oid] = {"id": oid, "nm": nm, "em": em, "ad": ad, "pm": pm, "ttl": sm["ttl"], "rows": sm["rows"]}
        r = JSONResponse({"ok": True, "id": oid})
        _ck_sv(r, {})
        return r

    @app.get("/api/shop/order/{oid}")
    async def api_ord_get(oid: str):
        o = ords.get(oid)
        if not o:
            raise HTTPException(404, "no order")
        return o

    @app.post("/api/shop/login")
    async def sh_lg(u: str = Form(...), p: str = Form(...)):
        if u == "admin" and p == "admin":
            return {"ok": True, "role": "admin"}
        return JSONResponse({"ok": False}, status_code=401)

    # --- Shop UI

    @app.get("/shop", response_class=HTMLResponse)
    async def sh_root(req: Request, q: str = "", cat: str = "all", srt: str = "rt_desc"):
        its = _flt(q, cat, srt)
        c = _ck_ld(req)
        sm = _ct_sum(c)
        return tpls.TemplateResponse(
            "shop.html",
            {"request": req, "q": q, "cat": cat, "srt": srt, "cats": _cats(), "it": its, "cart": sm, "msg": ""},
        )

    @app.get("/shop/item/{iid}", response_class=HTMLResponse)
    async def sh_i(req: Request, iid: int):
        it = next((x for x in _itms() if x["id"] == iid), None)
        if not it:
            raise HTTPException(404, "no item")
        c = _ck_ld(req)
        sm = _ct_sum(c)
        return tpls.TemplateResponse("item.html", {"request": req, "it": it, "cart": sm})

    @app.post("/shop/cart/add", response_class=HTMLResponse)
    async def sh_ca(req: Request, iid: int = Form(...), q: int = Form(1)):
        c = _ck_ld(req)
        c[str(int(iid))] = int(c.get(str(int(iid)), 0)) + max(1, int(q))
        r = RedirectResponse(url="/shop/cart", status_code=303)
        _ck_sv(r, c)
        return r

    @app.get("/shop/cart", response_class=HTMLResponse)
    async def sh_cart(req: Request):
        c = _ck_ld(req)
        sm = _ct_sum(c)
        return tpls.TemplateResponse("cart.html", {"request": req, "cart": sm})

    @app.post("/shop/cart/rm", response_class=HTMLResponse)
    async def sh_cart_rm(req: Request, iid: int = Form(...)):
        c = _ck_ld(req)
        c.pop(str(int(iid)), None)
        r = RedirectResponse(url="/shop/cart", status_code=303)
        _ck_sv(r, c)
        return r

    @app.get("/shop/checkout", response_class=HTMLResponse)
    async def sh_chk(req: Request):
        c = _ck_ld(req)
        sm = _ct_sum(c)
        if not sm["rows"]:
            return RedirectResponse(url="/shop/cart", status_code=303)
        return tpls.TemplateResponse("checkout.html", {"request": req, "cart": sm, "err": ""})

    @app.post("/shop/checkout", response_class=HTMLResponse)
    async def sh_chk_post(
        req: Request,
        nm: str = Form(...),
        em: str = Form(...),
        ad: str = Form(...),
        pm: str = Form("card"),
    ):
        c = _ck_ld(req)
        sm = _ct_sum(c)
        if not sm["rows"]:
            return RedirectResponse(url="/shop/cart", status_code=303)
        if "@" not in em or len(nm.strip()) < 2 or len(ad.strip()) < 6:
            return tpls.TemplateResponse("checkout.html", {"request": req, "cart": sm, "err": "проверь поля"})
        oid = secrets.token_hex(8)
        ords[oid] = {"id": oid, "nm": nm, "em": em, "ad": ad, "pm": pm, "ttl": sm["ttl"], "rows": sm["rows"]}
        r = RedirectResponse(url=f"/shop/order/{oid}", status_code=303)
        _ck_sv(r, {})
        return r

    @app.get("/shop/order/{oid}", response_class=HTMLResponse)
    async def sh_ord(req: Request, oid: str):
        o = ords.get(oid)
        if not o:
            raise HTTPException(404, "no order")
        return tpls.TemplateResponse("order.html", {"request": req, "o": o})

    return app
