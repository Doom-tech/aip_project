import pytest

from waflite.core import Rl, nrq, mtch, scr, dec, CfgErr


def test_nrq_keys():
    d = nrq({"ip": 1, "req": 2, "ua": 3, "st": "200"})
    assert set(d.keys()) == {"ip", "req", "ua", "st"}
    assert d["st"] == 200


@pytest.mark.parametrize(
    "rl,rq,exp",
    [
        (Rl("a", "sub", 1, ("../",), "req"), {"req": "/../../etc/passwd"}, True),
        (Rl("a", "sub", 1, ("../",), "req"), {"req": "/ok"}, False),
        (Rl("b", "re", 1, (r"\bselect\b",), "req"), {"req": "SELECT 1"}, True),
        (Rl("b", "re", 1, (r"\bselect\b",), "req"), {"req": "hello"}, False),
    ],
)
def test_mtch_ok(rl, rq, exp):
    assert mtch(rl, rq) is exp


def test_mtch_bad_type():
    with pytest.raises(CfgErr):
        mtch(Rl("x", "zzz", 1, ("a",), "req"), {"req": "a"})


def test_scr_and_dec_pos_neg():
    rls = [
        Rl("t1", "sub", 4, ("../",), "req"),
        Rl("t2", "re", 5, (r"<\s*script\b",), "req"),
    ]
    s1, ms1 = scr(rls, {"req": "/../../etc/passwd"})
    assert s1 == 4 and "t1" in ms1
    assert dec(s1, 7) == "allow"

    s2, ms2 = scr(rls, {"req": "/?q=<script>alert(1)</script>"})
    assert s2 == 5 and "t2" in ms2
    assert dec(s2, 5) == "block"
