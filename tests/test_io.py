import pytest

from waflite.io import prs_ng, prs_raw, prs, InpErr


def test_prs_raw_short():
    r = prs_raw("GET / HTTP/1.1")
    assert r.req.startswith("GET")
    assert r.ip == ""


def test_prs_raw_full():
    r = prs_raw("1.2.3.4\tGET /x HTTP/1.1\tUA")
    assert r.ip == "1.2.3.4"
    assert r.ua == "UA"


def test_prs_raw_bad():
    with pytest.raises(InpErr):
        prs_raw("a\tb")


def test_prs_ng_ok():
    ln = '10.0.0.2 - - [17/Dec/2025:10:00:01 +0000] "GET /x HTTP/1.1" 200 12 "-" "Mozilla/5.0"'
    r = prs_ng(ln)
    assert r.ip == "10.0.0.2"
    assert r.st == 200


def test_prs_ng_bad():
    with pytest.raises(InpErr):
        prs_ng("not a log line")


def test_prs_dispatch():
    assert prs("raw", "GET / HTTP/1.1").req.startswith("GET")
    with pytest.raises(InpErr):
        prs("zzz", "x")
