"""Address -> symbol resolution, including non-contiguous functions (issue #4)."""

from __future__ import annotations

from binja_delink.model import Arch, Function, Model, Reloc, Section, SegClass, Symbol
from binja_delink.resolver import DATA_START, SymbolResolver

TEXT = Section("text", 0x1000, 0x2000, True, False, True, SegClass.CODE)
DATA = Section("data", 0x2000, 0x2100, True, True, False, SegClass.DATA)


def make_resolver(functions, symbols=(), relocs=()):
    model = Model(arch=Arch.X86_64, bits=64, little_endian=True, image_base=0x1000,
                  filetype="ELF", input_file="sample", sections=[TEXT, DATA],
                  functions=list(functions), symbols=list(symbols), relocations=list(relocs))
    return SymbolResolver(model, list(relocs))


def test_address_in_a_gap_belongs_to_the_other_function():
    split_fn = Function(0x1000, 0, "split_fn", ranges=((0x1000, 0x1010), (0x1080, 0x10A0)))
    neighbour = Function(0x1010, 0x1080, "neighbour")
    resolver = make_resolver([split_fn, neighbour])
    assert resolver.resolve_code(0x1008) == ("split_fn", 8)
    assert resolver.resolve_code(0x1040) == ("neighbour", 0x30)
    assert resolver.resolve_code(0x1084) == ("split_fn", 0x14)   # second range, packed


def test_addends_are_relative_to_the_entry_point():
    reordered = Function(0x1080, 0, "reordered", ranges=((0x1000, 0x1010), (0x1080, 0x10A0)))
    resolver = make_resolver([reordered])
    assert resolver.resolve_code(0x1080) == ("reordered", 0)     # the symbol itself
    assert resolver.resolve_code(0x1000) == ("reordered", -0x10)


def test_data_falls_back_to_a_section_start_symbol():
    resolver = make_resolver([], symbols=[Symbol(0x2000, "known")])
    assert resolver.resolve_data(0x2000) == ("known", 0)
    assert resolver.resolve_data(0x2040) == (DATA_START, 0x40)
    assert resolver.resolve_data(0x9999) is None


def test_relocations_are_queried_by_range():
    relocs = [Reloc(0x2000, "ABS", 8, 0x1000), Reloc(0x2020, "ABS", 8, 0x1000)]
    resolver = make_resolver([], relocs=relocs)
    assert [r.addr for r in resolver.relocs_in(0x2000, 0x2010)] == [0x2000]
    assert [r.addr for r in resolver.relocs_in(0x2000, 0x2100)] == [0x2000, 0x2020]


def test_a_second_section_of_a_class_gets_its_own_start_symbol():
    # Images with several CONST segments (a PE carrying debug sections, say)
    # used to resolve every one of them against the first, so an address in
    # the second became an offset from the wrong base and was dropped or,
    # worse, silently pointed elsewhere.
    const_a = Section("const_a", 0x3000, 0x3100, True, False, False, SegClass.CONST)
    const_b = Section("const_b", 0x4000, 0x4100, True, False, False, SegClass.CONST)
    model = Model(arch=Arch.X86_64, bits=64, little_endian=True, image_base=0x1000,
                  filetype="PE", input_file="sample",
                  sections=[TEXT, DATA, const_a, const_b],
                  functions=[], symbols=[], relocations=[])
    resolver = SymbolResolver(model, [])
    assert resolver.resolve_data(0x3040) == ("__delink_const_start", 0x40)
    assert resolver.resolve_data(0x4040) == ("__delink_const_start_4000", 0x40)


def test_a_symbol_outside_the_first_section_of_its_class_is_still_a_variable():
    const_a = Section("const_a", 0x3000, 0x3100, True, False, False, SegClass.CONST)
    const_b = Section("const_b", 0x4000, 0x4100, True, False, False, SegClass.CONST)
    table = Symbol(0x4020, "jump_table_4020", public=False)
    model = Model(arch=Arch.X86_64, bits=64, little_endian=True, image_base=0x1000,
                  filetype="PE", input_file="sample",
                  sections=[TEXT, DATA, const_a, const_b],
                  functions=[], symbols=[table], relocations=[])
    resolver = SymbolResolver(model, [])
    assert 0x4020 in resolver.variables
