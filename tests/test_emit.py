"""Split orchestration: stats, visibility, duplicates, ranges (issues #2, #4, #8, #10, #11)."""

from __future__ import annotations

from binja_delink import emit
from binja_delink.grouping import SymbolDef
from binja_delink.model import Arch, Function, Model, Section, SegClass, Symbol
from binja_delink.objwrite.relocs import RelocKind
from binja_delink.recover.interface import RecoveredReloc
from binja_delink.resolver import SymbolResolver

TEXT = Section("text", 0x1000, 0x2000, True, False, True, SegClass.CODE)
DATA = Section("data", 0x2000, 0x2100, True, True, False, SegClass.DATA)


def make_model(functions, symbols=(), relocations=()):
    return Model(arch=Arch.X86_64, bits=64, little_endian=True, image_base=0x1000,
                 filetype="PE", input_file="sample.exe", sections=[TEXT, DATA],
                 functions=list(functions), symbols=list(symbols),
                 relocations=list(relocations))


def image_bytes(image):
    return next(s.data for s in image.sections if s.name == ".text")


def fill(byte: int):
    def bytes_fn(va: int, length: int) -> bytes:
        return bytes([byte]) * length
    return bytes_fn


def addressed_bytes(va: int, length: int) -> bytes:
    """Readable memory whose contents identify the address they came from."""
    return bytes((va + i) & 0xFF for i in range(length))


def no_relocs(_func, _data):
    return []


def test_skipped_function_is_counted_and_reported():
    model = make_model([Function(0x1000, 0x1010, "f")])
    resolver = SymbolResolver(model, [])
    group = {"f": SymbolDef(0x1000, 0x10, "static")}
    image, stats = emit.build_group_image(
        model, resolver, group, lambda va, length: None, no_relocs, "coff")
    assert stats.skipped_functions == 1
    assert stats.functions == 0
    assert image_bytes(image) == b""
    assert any("cannot read" in w for w in stats.warnings)


def test_unresolved_relocation_is_counted():
    model = make_model([Function(0x1000, 0x1010, "f")])
    resolver = SymbolResolver(model, [])

    def recover(_func, _data):
        return [RecoveredReloc(4, 0x9999, RelocKind.PCREL32, 4)]   # outside every section

    _image, stats = emit.build_group_image(
        model, resolver, {"f": SymbolDef(0x1000, 0x10, "static")}, fill(0x90), recover, "coff")
    assert stats.unresolved == 1
    assert stats.relocations == 0


def test_relocation_kind_the_format_cannot_write_is_dropped_not_guessed():
    model = make_model([Function(0x1000, 0x1010, "f")], symbols=[Symbol(0x2000, "datum")])
    model.arch = Arch.AARCH64
    resolver = SymbolResolver(model, [])

    def recover(_func, _data):
        return [RecoveredReloc(0, 0x2000, RelocKind.AARCH64_LD_PREL_LO19, 4)]

    _image, stats = emit.build_group_image(
        model, resolver, {"f": SymbolDef(0x1000, 0x10, "static")}, fill(0), recover, "coff")
    assert (stats.unsupported, stats.relocations) == (1, 0)
    # ELF has R_AARCH64_LD_PREL_LO19, so the same relocation survives there.
    _image, stats = emit.build_group_image(
        model, resolver, {"f": SymbolDef(0x1000, 0x10, "static")}, fill(0), recover, "elf")
    assert (stats.unsupported, stats.relocations) == (0, 1)


def test_non_contiguous_function_emits_only_its_own_bytes():
    func = Function(0x1000, 0, "f", ranges=((0x1000, 0x1010), (0x1080, 0x10A0)))
    model = make_model([func, Function(0x1010, 0x1080, "neighbour")])
    resolver = SymbolResolver(model, [])
    image, stats = emit.build_group_image(
        model, resolver, {"f": SymbolDef(0x1000, func.size(), "global")},
        addressed_bytes, no_relocs, "coff")
    text = image_bytes(image)
    assert len(text) == 0x30                       # 0x10 + 0x20, gap dropped
    assert text[:0x10] == addressed_bytes(0x1000, 0x10)
    assert text[0x10:] == addressed_bytes(0x1080, 0x20)
    assert stats.text_bytes == 0x30
    assert image.symbols[0].value == 0             # entry is the first range here


def test_symbol_sits_at_the_entry_point_of_a_reordered_function():
    func = Function(0x1080, 0, "f", ranges=((0x1000, 0x1010), (0x1080, 0x10A0)))
    model = make_model([func])
    resolver = SymbolResolver(model, [])
    image, _stats = emit.build_group_image(
        model, resolver, {"f": SymbolDef(0x1080, func.size(), "global")},
        addressed_bytes, no_relocs, "coff")
    assert image.symbols[0].value == 0x10


def test_duplicate_names_in_one_object_get_separate_definitions():
    var_model = make_model([], symbols=[Symbol(0x2000, "counter"), Symbol(0x2010, "counter")])
    resolver = SymbolResolver(var_model, [])
    image, stats = emit.emit_shared(var_model, resolver, fill(0))
    defined = [s.name for s in image.symbols if s.section_index != 0]
    assert len(defined) == len(set(defined))       # no duplicate definitions
    assert "counter" in defined and "counter_2010" in defined
    assert stats.renamed_symbols == 1


def test_cross_object_reference_makes_the_definition_global():
    model = make_model([Function(0x1000, 0x1010, "caller"), Function(0x1010, 0x1020, "callee")])
    resolver = SymbolResolver(model, [])

    def recover(func, _data):
        if func.name != "caller":
            return []
        return [RecoveredReloc(1, 0x1010, RelocKind.PCREL32, 4)]

    groups = {
        "caller.obj": {"caller": SymbolDef(0x1000, 0x10, "static")},
        "callee.obj": {"callee": SymbolDef(0x1010, 0x10, "static")},   # PE: everything static
    }
    images, stats = emit.split(model, resolver, groups, fill(0x90), recover, "coff")
    callee = dict(images)["callee.obj"]
    definition = next(s for s in callee.symbols if s.name == "callee")
    assert definition.is_global                    # else the link cannot resolve it
    assert stats.promoted_symbols == 1
    caller = dict(images)["caller.obj"]
    assert not next(s for s in caller.symbols if s.name == "caller").is_global


def test_output_extensions_follow_the_format():
    model = make_model([Function(0x1000, 0x1010, "f")])
    resolver = SymbolResolver(model, [])
    groups = {"f.obj": {"f": SymbolDef(0x1000, 0x10, "static")}}
    images, stats = emit.split(model, resolver, groups, fill(0x90), no_relocs, "elf")
    names = [name for name, _image in images]
    assert names == ["f.o", "__shared_data.o"]
    assert any("renamed" in w for w in stats.warnings)
    images, _stats = emit.split(model, resolver, groups, fill(0x90), no_relocs, "coff")
    assert [name for name, _image in images] == ["f.obj", "__shared_data.obj"]


def test_duplicate_global_definitions_across_objects_are_reported():
    model = make_model([Function(0x1000, 0x1010, "dup"), Function(0x1010, 0x1020, "dup")])
    resolver = SymbolResolver(model, [])
    groups = {
        "a.obj": {"dup": SymbolDef(0x1000, 0x10, "global")},
        "b.obj": {"dup": SymbolDef(0x1010, 0x10, "global")},
    }
    _images, stats = emit.split(model, resolver, groups, fill(0x90), no_relocs, "coff")
    assert any("defined globally by a.obj, b.obj" in w for w in stats.warnings)


def test_stats_summary_reports_what_was_written():
    model = make_model([Function(0x1000, 0x1010, "f")])
    resolver = SymbolResolver(model, [])
    groups = {"f.obj": {"f": SymbolDef(0x1000, 0x10, "static")}}
    _images, stats = emit.split(model, resolver, groups, fill(0x90), no_relocs, "coff")
    assert stats.objects == 2                      # one group plus the shared-data object
    assert stats.functions == 1
    assert "1 functions" in stats.summary()
