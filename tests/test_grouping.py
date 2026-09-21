"""grouping serialisation and extension handling (issues #9, #11)."""

from __future__ import annotations

import json

from binja_delink.grouping import SymbolDef, load, retarget_extensions, save


def test_non_ascii_names_are_written_as_utf8(tmp_path):
    path = tmp_path / "binja.json"
    save({"a.o": {"café_init": SymbolDef(0x1000, 4, "global")}}, str(path))
    raw = path.read_bytes()
    assert "café_init".encode("utf-8") in raw   # serde_json writes raw UTF-8
    assert b"\\u00e9" not in raw


def test_saved_layout_matches_delink(tmp_path):
    path = tmp_path / "binja.json"
    groups = {
        "b.o": {"z": SymbolDef(2, 2, "static"), "a": SymbolDef(1, 1, "global")},
        "a.o": {"q": SymbolDef(3, 3, "static")},
    }
    save(groups, str(path))
    text = path.read_text(encoding="utf-8")
    assert text.index('"a.o"') < text.index('"b.o"')          # outer keys sorted
    assert text.index('"a":') < text.index('"z":')            # inner keys sorted
    first = json.loads(text)["b.o"]["a"]
    assert list(first) == ["address", "size", "scope"]        # declaration order
    assert load(str(path))["b.o"]["a"] == SymbolDef(1, 1, "global")


def test_extensions_follow_the_requested_format():
    groups = {"a.obj": {"a": SymbolDef(1, 1, "static")}, "b.obj": {"b": SymbolDef(2, 1, "static")}}
    out, warnings = retarget_extensions(groups, "o")
    assert sorted(out) == ["a.o", "b.o"]
    assert len(warnings) == 2


def test_matching_extensions_are_left_alone():
    groups = {"a.o": {"a": SymbolDef(1, 1, "static")}}
    out, warnings = retarget_extensions(groups, "o")
    assert list(out) == ["a.o"]
    assert warnings == []


def test_name_without_extension_gains_one():
    out, _warnings = retarget_extensions({"noext": {"a": SymbolDef(1, 1, "static")}}, "obj")
    assert list(out) == ["noext.obj"]
