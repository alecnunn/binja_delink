"""Field location and AArch64 classification (issues #5, #6)."""

from __future__ import annotations

from binja_delink.objwrite.aarch64 import set_imm12, set_imm19, set_imm21
from binja_delink.objwrite.relocs import RelocKind
from binja_delink.recover.arm64 import aarch64_branch_reloc, aarch64_data_reloc
from binja_delink.recover.interface import (
    FieldClaims, find_abs_field, find_abs_fields, find_pcrel_field, find_pcrel_fields,
)


def test_both_fields_of_one_instruction_are_found():
    # i386 `mov dword ptr [0x404000], 0x404000`: C7 05 <disp32> <imm32>.
    instr = bytes.fromhex("c705") + (0x404000).to_bytes(4, "little") * 2
    assert find_abs_fields(instr, 0x404000, 4) == [2, 6]
    # The ModRM displacement, not the trailing immediate.
    assert find_abs_field(instr, 0x404000, 4) == 2


def test_absolute_field_wider_than_the_instruction():
    assert find_abs_fields(bytes(4), 0x404000, 8) == []


def test_pcrel_fields_are_reported_in_order():
    # Two 4-byte windows that both resolve to the target from the same next_ip.
    instr = bytes.fromhex("0f1f") + (0x10).to_bytes(4, "little") + (0x10).to_bytes(4, "little")
    matches = find_pcrel_fields(instr, 0x1000, len(instr), 0x1000 + len(instr) + 0x10)
    assert [off for off, _trailing in matches] == [2, 6]
    assert matches[1][1] == 0                        # last field has no trailing bytes


def test_pcrel_single_field_prefers_the_displacement_at_the_end():
    instr = bytes.fromhex("e8") + (0x20).to_bytes(4, "little")
    assert find_pcrel_field(instr, 0x1000, 5, 0x1025) == (1, 0)


def test_claims_reject_overlapping_fields():
    claims = FieldClaims()
    assert claims.claim(2, 4)
    assert not claims.claim(4, 4)                    # overlaps bytes 4..5
    assert claims.claim(6, 4)


def test_aarch64_branches():
    bl = 0x94000000 | 4
    b = 0x14000000 | 4
    assert aarch64_branch_reloc(bl, is_call=True).kind == RelocKind.AARCH64_CALL26
    assert aarch64_branch_reloc(b, is_call=False).kind == RelocKind.AARCH64_JUMP26
    assert aarch64_branch_reloc(0xD65F03C0, is_call=False) is None   # RET


def test_adrp_add_pair_is_recovered():
    # adrp x0, 0x404000 at 0x401000 -> three pages up; add x0, x0, #0x10.
    adrp = set_imm21(0x90000000, 3)
    rec = aarch64_data_reloc(adrp, 0x401000, 0x404010)
    assert rec is not None and rec.kind == RelocKind.AARCH64_ADR_PREL_PG_HI21
    add = set_imm12(0x91000000, 0x10)
    rec = aarch64_data_reloc(add, 0x401004, 0x404010)
    assert rec is not None and rec.kind == RelocKind.AARCH64_ADD_ABS_LO12_NC


def test_ldr_page_offset_is_scaled_by_access_size():
    ldr = set_imm12(0xF9400000, 2)                   # ldr x1, [x0, #0x10]
    rec = aarch64_data_reloc(ldr, 0x401008, 0x404010)
    assert rec is not None and rec.kind == RelocKind.AARCH64_LDST64_ABS_LO12_NC
    ldrb = set_imm12(0x39400000, 0x10)               # ldrb w1, [x0, #0x10]
    rec = aarch64_data_reloc(ldrb, 0x401008, 0x404010)
    assert rec is not None and rec.kind == RelocKind.AARCH64_LDST8_ABS_LO12_NC


def test_adr_and_ldr_literal():
    adr = set_imm21(0x10000000, 0x20)
    rec = aarch64_data_reloc(adr, 0x401000, 0x401020)
    assert rec is not None and rec.kind == RelocKind.AARCH64_ADR_PREL_LO21
    ldr_lit = set_imm19(0x58000000, 0x40)
    rec = aarch64_data_reloc(ldr_lit, 0x401000, 0x401040)
    assert rec is not None and rec.kind == RelocKind.AARCH64_LD_PREL_LO19


def test_instruction_whose_immediate_misses_the_target_is_not_claimed():
    add = set_imm12(0x91000000, 0x10)
    assert aarch64_data_reloc(add, 0x401004, 0x404020) is None
    assert aarch64_data_reloc(0xD503201F, 0x401000, 0x404010) is None   # NOP
