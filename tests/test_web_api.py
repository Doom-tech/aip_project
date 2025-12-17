from pathlib import Path

from fastapi.testclient import TestClient

from waflite.webapp import mk_app


def test_api_tst_and_block(tmp_path: Path):
    dbp = tmp_path / "db.json"
    dbp.write_text(
        """
        {
          "thr": 7,
          "ign_ua": [],
          "rls": [
            {"rid":"sqli_x","rtp":"re","w":7,"ps":["UNION"],"fld":"req"}
          ]
        }
        """.strip(),
        encoding="utf-8",
    )
    c = TestClient(mk_app(dbp))
    r = c.post("/api/tst", json={"req": "GET /?id=1 UNION SELECT 1 HTTP/1.1", "ua": "Mozilla/5.0"})
    assert r.status_code == 200
    j = r.json()
    assert j["dec"] == "block"

    r2 = c.get("/shop/search?q=1%20UNION%20SELECT%201")
    assert r2.status_code == 403
    assert "blocked by waflite" in r2.text
