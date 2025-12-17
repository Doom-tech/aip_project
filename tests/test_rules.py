import json
from pathlib import Path

import pytest

from waflite.rules import ld_cfg, ld_rls
from waflite.core import CfgErr


def test_ld_cfg_default():
    d = ld_cfg(None)
    thr, rls, ign = ld_rls(d)
    assert thr >= 1
    assert len(rls) >= 1
    assert ign == []


def test_ld_cfg_file(tmp_path: Path):
    p = tmp_path / "cfg.json"
    p.write_text(
        json.dumps({"thr": 3, "rls": [{"rid": "a", "rtp": "sub", "w": 1, "ps": ["x"]}]}),
        encoding="utf-8",
    )
    d = ld_cfg(p)
    thr, rls, _ = ld_rls(d)
    assert thr == 3
    assert rls[0].rid == "a"


def test_ld_cfg_bad_json(tmp_path: Path):
    p = tmp_path / "cfg.json"
    p.write_text("{", encoding="utf-8")
    with pytest.raises(CfgErr):
        ld_cfg(p)


def test_ld_rls_missing_fields():
    with pytest.raises(CfgErr):
        ld_rls({"thr": 1, "rls": [{"rid": "a"}]})
