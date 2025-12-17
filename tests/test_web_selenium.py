import os
import threading
import time
from pathlib import Path

import pytest

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
except Exception:  # pragma: no cover
    webdriver = None


@pytest.mark.skipif(webdriver is None, reason="selenium not installed")
def test_ui_add_rule_and_block(tmp_path: Path):
    # Если нет chromedriver/geckodriver, тест будет падать.
    # Поэтому делаем мягкий skip по env.
    if not os.environ.get("WAF_SELENIUM"):
        pytest.skip("set WAF_SELENIUM=1 to run selenium tests")

    from waflite.webapp import mk_app
    import uvicorn

    dbp = tmp_path / "db.json"
    dbp.write_text('{"thr": 7, "ign_ua": [], "rls": []}', encoding="utf-8")

    cfg = uvicorn.Config(mk_app(dbp), host="127.0.0.1", port=8765, log_level="warning")
    srv = uvicorn.Server(cfg)

    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    time.sleep(0.8)

    # driver (по умолчанию chrome)
    br = os.environ.get("WAF_BR", "chrome").lower()
    if br == "firefox":
        d = webdriver.Firefox()
    else:
        opt = webdriver.ChromeOptions()
        opt.add_argument("--headless=new")
        opt.add_argument("--no-sandbox")
        opt.add_argument("--disable-dev-shm-usage")
        d = webdriver.Chrome(options=opt)

    try:
        d.get("http://127.0.0.1:8765/ui")
        d.find_element(By.NAME, "rid").send_keys("sqli_z")
        d.find_element(By.NAME, "wv").clear()
        d.find_element(By.NAME, "wv").send_keys("7")
        sel = d.find_element(By.NAME, "rtp")
        # default re ok
        d.find_element(By.NAME, "ps").send_keys(r"\bUNION\b")
        d.find_element(By.CSS_SELECTOR, "button.btn.btn-primary").click()
        time.sleep(0.2)

        d.get("http://127.0.0.1:8765/shop/search?q=1%20UNION%20SELECT%201")
        body = d.page_source.lower()
        assert "blocked by waflite" in body
    finally:
        d.quit()
        srv.should_exit = True
