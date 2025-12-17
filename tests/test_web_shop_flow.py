from pathlib import Path

from fastapi.testclient import TestClient

from waflite.webapp import mk_app


def test_shop_cart_checkout_ok(tmp_path: Path):
    dbp = tmp_path / "db.json"
    dbp.write_text(
        """
        {
          "thr": 50,
          "ign_ua": [],
          "rls": []
        }
        """.strip(),
        encoding="utf-8",
    )
    c = TestClient(mk_app(dbp))

    r = c.get("/shop")
    assert r.status_code == 200

    r = c.post("/shop/cart/add", data={"iid": 2, "q": 2}, follow_redirects=False)
    assert r.status_code in (302, 303)
    ck = r.cookies.get("cart")
    assert ck

    c.cookies.set("cart", ck)

    r = c.get("/shop/cart")
    assert r.status_code == 200
    assert "YubiKey" in r.text

    r = c.get("/shop/checkout")
    assert r.status_code == 200

    r = c.post("/shop/checkout", data={"nm": "Ivan", "em": "a@b.c", "ad": "Street 1", "pm": "card"}, follow_redirects=False)
    assert r.status_code in (302, 303)
    assert r.headers["location"].startswith("/shop/order/")
