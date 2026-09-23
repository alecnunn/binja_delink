"""Adapter behaviour against a stubbed BinaryView (issues #4, #5, #6, #7)."""

from __future__ import annotations

import struct

import fake_binaryninja

fake_binaryninja.install()

from binja_delink import binja_adapter                       # noqa: E402  (needs the stub first)
from binja_delink.model import Arch                          # noqa: E402
from binja_delink.objwrite.aarch64 import set_imm12, set_imm21  # noqa: E402
from binja_delink.objwrite.relocs import RelocKind           # noqa: E402

BranchType = fake_binaryninja.BranchType
InstructionInfo = fake_binaryninja.InstructionInfo
RelocationInfo = fake_binaryninja.RelocationInfo


def make_bv(**kwargs):
    arch = fake_binaryninja.Architecture(
        kwargs.pop("arch_name", "x86_64"), kwargs.pop("address_size", 8),
        kwargs.pop("instructions", {}))
    bv = fake_binaryninja.BinaryView(arch, kwargs.pop("memory", {}), **kwargs)
    return bv, arch


def test_relocation_width_comes_from_binary_ninja_not_the_pointer_size():
    # A 4-byte relocation in a 64-bit image: reading a pointer-sized word here
    # would take its size and target from the following bytes as well.
    bv, _arch = make_bv(
        memory={0x2000: b"\x00\x40\x40\x00" + b"\xff" * 8},
        relocation_ranges=[(0x2000, 0x2004)],
        relocations={0x2000: [RelocationInfo(size=4, target=0x404000, addend=0)]})
    relocs = binja_adapter._read_relocations(bv, ptr_size=8)
    assert len(relocs) == 1
    assert (relocs[0].size, relocs[0].target, relocs[0].addr) == (4, 0x404000, 0x2000)


def test_relocation_details_are_carried_through():
    bv, _arch = make_bv(
        memory={0x2000: b"\x00" * 16},
        relocation_ranges=[(0x2000, 0x2008)],
        relocations={0x2000: [RelocationInfo(size=8, target=0x401000, addend=0x20,
                                             pc_relative=True, data_relocation=False)]})
    reloc = binja_adapter._read_relocations(bv, ptr_size=8)[0]
    assert (reloc.kind, reloc.addend, reloc.pc_relative, reloc.data) == ("PCREL", 0x20, True, False)


def test_addresses_without_a_relocation_object_fall_back_to_the_stored_word():
    bv, _arch = make_bv(
        memory={0x2000: struct.pack("<Q", 0x401234)},
        relocation_ranges=[(0x2000, 0x2008)], relocations={})
    reloc = binja_adapter._read_relocations(bv, ptr_size=8)[0]
    assert (reloc.size, reloc.target) == (8, 0x401234)


def test_function_ranges_reach_the_model():
    bv, arch = make_bv()
    bv.functions.append(fake_binaryninja.Function(
        0x1000, [(0x1000, 0x1010), (0x1080, 0x10A0)], "split_fn", arch))
    model = binja_adapter.build_model(bv)
    func = model.functions[0]
    assert func.ranges == ((0x1000, 0x1010), (0x1080, 0x10A0))
    assert func.size() == 0x30                    # not 0xA0: the gap is someone else's


def test_both_fields_of_one_instruction_get_a_relocation():
    # i386 `mov dword ptr [0x404000], 0x404000`: displacement and immediate.
    instr = bytes.fromhex("c705") + (0x404000).to_bytes(4, "little") * 2
    bv, arch = make_bv(
        arch_name="x86", address_size=4,
        instructions={0x1000: InstructionInfo(len(instr))},
        memory={0x1000: instr},
        code_refs={0x1000: [0x404000]},
        segments=[fake_binaryninja.Segment(0x404000, 0x405000, True, True, False, 0x1000)])
    func = fake_binaryninja.Function(0x1000, [(0x1000, 0x100A)], "f", arch)
    bv.functions.append(func)
    model = binja_adapter.build_model(bv)
    recovered = binja_adapter.make_recover_fn(bv, model)(model.functions[0], instr)
    assert [(r.offset, r.kind) for r in recovered] == [
        (2, RelocKind.ABS32), (6, RelocKind.ABS32)]


def test_branch_into_another_function_is_not_treated_as_intra_function():
    # A call whose target sits in the gap between two ranges of the caller.
    call = b"\xe8" + struct.pack("<i", 0x1040 - 0x1005)
    text = call + b"\x90" * 11
    bv, arch = make_bv(
        instructions={0x1000: InstructionInfo(5, [fake_binaryninja.Branch(
            BranchType.CallDestination, 0x1040)])},
        memory={0x1000: text, 0x1080: b"\x90" * 16},
        segments=[fake_binaryninja.Segment(0x1000, 0x2000, True, False, True, 0x1000)])
    func = fake_binaryninja.Function(
        0x1000, [(0x1000, 0x1010), (0x1080, 0x1090)], "f", arch, blocks=[(0x1000, 0x1005)])
    bv.functions.append(func)
    bv.functions.append(fake_binaryninja.Function(0x1040, [(0x1040, 0x1050)], "neighbour", arch))
    model = binja_adapter.build_model(bv)
    data = text[:0x10] + b"\x90" * 0x10
    recovered = binja_adapter.make_recover_fn(bv, model)(model.functions[0], data)
    assert [(r.offset, r.kind) for r in recovered] == [(1, RelocKind.PCREL32)]


def test_aarch64_data_references_are_recovered():
    adrp = set_imm21(0x90000000, 3)               # adrp x0, 0x404000 from 0x401000
    add = set_imm12(0x91000000, 0x10)             # add x0, x0, #0x10
    text = struct.pack("<II", adrp, add)
    bv, arch = make_bv(
        arch_name="aarch64",
        instructions={0x401000: InstructionInfo(4), 0x401004: InstructionInfo(4)},
        memory={0x401000: text},
        code_refs={0x401000: [0x404010], 0x401004: [0x404010]},
        segments=[fake_binaryninja.Segment(0x404000, 0x405000, True, True, False, 0x1000)])
    bv.functions.append(fake_binaryninja.Function(0x401000, [(0x401000, 0x401008)], "f", arch))
    model = binja_adapter.build_model(bv)
    assert model.arch == Arch.AARCH64
    recovered = binja_adapter.make_recover_fn(bv, model)(model.functions[0], text)
    assert [(r.offset, r.kind) for r in recovered] == [
        (0, RelocKind.AARCH64_ADR_PREL_PG_HI21),
        (4, RelocKind.AARCH64_ADD_ABS_LO12_NC),
    ]


def test_recovered_offsets_are_relative_to_the_emitted_bytes():
    # The reference lives in the second range, which follows the first one
    # directly in the object even though a gap separates them in the image.
    instr = bytes.fromhex("c705") + (0x404000).to_bytes(4, "little") * 2
    bv, arch = make_bv(
        arch_name="x86", address_size=4,
        instructions={0x1080: InstructionInfo(len(instr))},
        memory={0x1000: b"\x90" * 16, 0x1080: instr},
        code_refs={0x1080: [0x404000]},
        segments=[fake_binaryninja.Segment(0x404000, 0x405000, True, True, False, 0x1000)])
    func = fake_binaryninja.Function(
        0x1000, [(0x1000, 0x1010), (0x1080, 0x108A)], "f", arch, blocks=[(0x1080, 0x108A)])
    bv.functions.append(func)
    model = binja_adapter.build_model(bv)
    data = b"\x90" * 16 + instr
    recovered = binja_adapter.make_recover_fn(bv, model)(model.functions[0], data)
    assert [r.offset for r in recovered] == [0x10 + 2, 0x10 + 6]


def test_a_reference_reported_only_as_a_code_ref_is_recovered():
    # Regression for the data-reference path querying get_data_refs_from on a
    # code address: the core files a reference originating at an INSTRUCTION
    # under code refs, so a recovery that only consults data refs sees nothing
    # and silently emits no relocation at all.
    instr = bytes.fromhex("c705") + (0x404000).to_bytes(4, "little") * 2
    bv, arch = make_bv(
        arch_name="x86", address_size=4,
        instructions={0x1000: InstructionInfo(len(instr))},
        memory={0x1000: instr},
        code_refs={0x1000: [0x404000]},
        data_refs={},                      # nothing here, as for a real code address
        segments=[fake_binaryninja.Segment(0x404000, 0x405000, True, True, False, 0x1000)])
    bv.functions.append(fake_binaryninja.Function(0x1000, [(0x1000, 0x100A)], "f", arch))
    model = binja_adapter.build_model(bv)
    recovered = binja_adapter.make_recover_fn(bv, model)(model.functions[0], instr)
    assert [r.kind for r in recovered] == [RelocKind.ABS32, RelocKind.ABS32]


def test_an_absolute_reference_narrower_than_a_pointer_is_found_on_a_64_bit_image():
    # x86_64 `add eax, [rdi*4 + 0x404040]`: the address is a 32-bit ModRM
    # displacement. Searching only at pointer width can never match inside a
    # 7-byte instruction, so this used to come back with no relocation.
    instr = bytes.fromhex("0304bd") + (0x404040).to_bytes(4, "little")
    bv, arch = make_bv(
        instructions={0x401000: InstructionInfo(len(instr))},
        memory={0x401000: instr},
        code_refs={0x401000: [0x404040]},
        segments=[fake_binaryninja.Segment(0x404000, 0x405000, True, True, False, 0x1000)])
    bv.functions.append(fake_binaryninja.Function(0x401000, [(0x401000, 0x401007)], "f", arch))
    model = binja_adapter.build_model(bv)
    recovered = binja_adapter.make_recover_fn(bv, model)(model.functions[0], instr)
    assert [(r.offset, r.kind, r.width) for r in recovered] == [(3, RelocKind.ABS32, 4)]


def test_one_relocation_reported_twice_at_an_address_is_emitted_once():
    info = RelocationInfo(size=8, target=0x401000, addend=0)
    bv, _arch = make_bv(
        memory={0x2000: b"\x00" * 16},
        relocation_ranges=[(0x2000, 0x2008)],
        relocations={0x2000: [info, info]})
    assert len(binja_adapter._read_relocations(bv, ptr_size=8)) == 1


def test_an_adrp_with_no_reported_reference_is_paired_with_its_consumer():
    # Binary Ninja files the pair's reference on the ADD/LDR that supplies the
    # low 12 bits and often reports nothing at all for the ADRP. The page an
    # ADRP names is usually in no section either, so both the target and the
    # section test have to come from the consumer.
    adrp = set_imm21(0x9000000C, 3)               # adrp x12, 0x404000 from 0x401000
    add = set_imm12(0x9100018C, 0x380)            # add x12, x12, #0x380
    text = struct.pack("<II", adrp, add)
    bv, arch = make_bv(
        arch_name="aarch64",
        instructions={0x401000: InstructionInfo(4), 0x401004: InstructionInfo(4)},
        memory={0x401000: text},
        code_refs={0x401004: [0x404380]},         # nothing reported at the ADRP
        segments=[fake_binaryninja.Segment(0x404000, 0x405000, True, True, False, 0x1000)])
    bv.functions.append(fake_binaryninja.Function(0x401000, [(0x401000, 0x401008)], "f", arch))
    model = binja_adapter.build_model(bv)
    recovered = binja_adapter.make_recover_fn(bv, model)(model.functions[0], text)
    assert [(r.offset, r.kind, r.target_va) for r in recovered] == [
        (0, RelocKind.AARCH64_ADR_PREL_PG_HI21, 0x404380),
        (4, RelocKind.AARCH64_ADD_ABS_LO12_NC, 0x404380),
    ]


def test_an_adrp_is_paired_across_a_basic_block_boundary():
    # "adrp x12, P / b.lt / ... / ldr [x12, #off]" is routine: resetting the
    # pairing state per basic block loses the page base entirely.
    adrp = set_imm21(0x9000000C, 3)
    add = set_imm12(0x9100018C, 0x380)
    text = struct.pack("<III", adrp, 0xD503201F, add)   # adrp / nop / add
    bv, arch = make_bv(
        arch_name="aarch64",
        instructions={a: InstructionInfo(4) for a in (0x401000, 0x401004, 0x401008)},
        memory={0x401000: text},
        code_refs={0x401008: [0x404380]},
        segments=[fake_binaryninja.Segment(0x404000, 0x405000, True, True, False, 0x1000)])
    bv.functions.append(fake_binaryninja.Function(
        0x401000, [(0x401000, 0x40100C)], "f", arch,
        blocks=[(0x401000, 0x401008), (0x401008, 0x40100C)]))   # split before the ADD
    model = binja_adapter.build_model(bv)
    recovered = binja_adapter.make_recover_fn(bv, model)(model.functions[0], text)
    assert (0, RelocKind.AARCH64_ADR_PREL_PG_HI21, 0x404380) in [
        (r.offset, r.kind, r.target_va) for r in recovered]
