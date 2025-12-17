from pathlib import Path

from fastapi.testclient import TestClient

from waflite.api import mk_api


def test_api_health(tmp_path: Path):
    dbp = tmp_path / "db.json"
    dbp.write_text('{"thr": 7, "ign_ua": [], "rls": []}', encoding="utf-8")
    c = TestClient(mk_api(dbp))
    r = c.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_api_scan_block(tmp_path: Path):
    dbp = tmp_path / "db.json"
    dbp.write_text(
        """
        {
          "thr": 7,
          "ign_ua": [],
          "rls": [
            {"rid":"sqli_x","rtp":"sub","w":7,"ps":["UNION"],"fld":"req"}
          ]
        }
        """.strip(),
        encoding="utf-8",
    )
    c = TestClient(mk_api(dbp))
    r = c.post("/api/v1/scan", json={"req": "GET /?id=1 UNION SELECT 1 HTTP/1.1", "ua": "Mozilla/5.0"})
    assert r.status_code == 200
    j = r.json()
    assert j["dec"] == "block"
    assert j["scr"] >= 7


def test_api_batch(tmp_path: Path):
    dbp = tmp_path / "db.json"
    dbp.write_text('{"thr": 99, "ign_ua": [], "rls": []}', encoding="utf-8")
    c = TestClient(mk_api(dbp))
    r = c.post(
        "/api/v1/batch",
        json={"items": [{"req": "GET / HTTP/1.1"}, {"req": "GET /x HTTP/1.1", "ua": "sqlmap"}]},
    )
    assert r.status_code == 200
    j = r.json()
    assert j["n"] == 2
    assert len(j["items"]) == 2


def test_api_rules_put_get(tmp_path: Path):
    dbp = tmp_path / "db.json"
    dbp.write_text('{"thr": 7, "ign_ua": [], "rls": []}', encoding="utf-8")
    c = TestClient(mk_api(dbp))
    new_db = {"thr": 5, "ign_ua": ["probe"], "rls": [{"rid": "x", "rtp": "sub", "w": 5, "ps": ["../"], "fld": "req"}]}
    r = c.put("/api/v1/rules", json=new_db)
    assert r.status_code == 200
    r2 = c.get("/api/v1/rules")
    assert r2.status_code == 200
    assert r2.json()["thr"] == 5
