"""Jump-table relocation recovery (issue #13).

A switch compiles to a table the image's own relocation table says nothing
about once it has been linked. Absolute tables need a relocation per entry;
the self-relative forms are position-independent already and must be left
untouched.
"""

from __future__ import annotations

import struct

import fake_binaryninja

fake_binaryninja.install()

from binja_delink import binja_adapter                       # noqa: E402

InstructionInfo = fake_binaryninja.InstructionInfo
RelocationInfo = fake_binaryninja.RelocationInfo

CODE = (0x401000, 0x402000)
CONST = (0x402000, 0x403000)
DESTS = (0x401020, 0x401030)
SOURCE = 0x401007
TABLE = 0x402000


def make_bv(table_bytes: bytes, address_size: int = 8, **kwargs):
    arch = fake_binaryninja.Architecture("x86_64" if address_size == 8 else "x86",
                                         address_size, {})
    bv = fake_binaryninja.BinaryView(
        arch, {TABLE: table_bytes},
        code_refs={SOURCE: list(DESTS) + [TABLE]},
        segments=[
            fake_binaryninja.Segment(*CODE, True, False, True, CODE[1] - CODE[0]),
            fake_binaryninja.Segment(*CONST, True, False, False, CONST[1] - CONST[0]),
        ],
        **kwargs)
    bv.functions.append(fake_binaryninja.Function(
        0x401000, [CODE], "big_switch", arch,
        indirect_branches=[(SOURCE, d) for d in DESTS]))
    return bv


def table_relocs(model):
    return [r for r in model.relocations if CONST[0] <= r.addr < CONST[1]]


def test_an_absolute_pointer_table_gets_a_relocation_per_entry():
    bv = make_bv(struct.pack("<QQ", *DESTS))
    relocs = table_relocs(binja_adapter.build_model(bv))
    assert [(r.addr, r.target, r.size) for r in relocs] == [
        (TABLE, DESTS[0], 8), (TABLE + 8, DESTS[1], 8)]


def test_a_self_relative_offset_table_is_left_alone():
    # PE/AArch64 style: the entries are biases from a base, not addresses.
    # Relocating them would corrupt data that is already position-independent.
    bv = make_bv(struct.pack("<QQ", 0x20, 0x30))
    assert table_relocs(binja_adapter.build_model(bv)) == []


def test_entries_the_image_already_relocates_are_not_relocated_twice():
    # A PE keeps base relocations for its absolute tables. A second fixup over
    # the image's own would double the stored value under COFF and ELF REL,
    # which both accumulate the addend in place.
    bv = make_bv(
        struct.pack("<QQ", *DESTS),
        relocation_ranges=[(TABLE, TABLE + 16)],
        relocations={TABLE: [RelocationInfo(size=8, target=DESTS[0], addend=0)],
                     TABLE + 8: [RelocationInfo(size=8, target=DESTS[1], addend=0)]})
    relocs = table_relocs(binja_adapter.build_model(bv))
    assert [r.addr for r in relocs] == [TABLE, TABLE + 8]      # the image's own, once each


def test_a_table_binary_ninja_typed_as_an_array_uses_that_shape():
    # Four entries, but only two distinct branch destinations: without the
    # array type the count would be guessed from the destinations and the last
    # two entries would keep their original addresses.
    bv = make_bv(struct.pack("<QQQQ", DESTS[0], DESTS[1], DESTS[0], DESTS[1]),
                 data_vars={TABLE: fake_binaryninja.DataVariable(
                     TABLE, fake_binaryninja.ArrayType(8, 4))})
    relocs = table_relocs(binja_adapter.build_model(bv))
    assert [r.addr for r in relocs] == [TABLE, TABLE + 8, TABLE + 16, TABLE + 24]
