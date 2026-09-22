"""aarch64 relocation classification (Binja-free).

AArch64 immediates are split across instruction-word bitfields rather than
stored in a contiguous little-endian field, so recovery here decodes the word
instead of scanning bytes for a window that reproduces the target.
"""

from __future__ import annotations

from binja_delink.objwrite.aarch64 import (
    get_imm12, get_imm19, get_imm21, ldst_scale,
)
from binja_delink.objwrite.relocs import RelocKind
from binja_delink.recover.interface import RecoveredReloc

_PAGE_MASK = ~0xFFF

_LDST_KIND_BY_SCALE = {
    0: RelocKind.AARCH64_LDST8_ABS_LO12_NC,
    1: RelocKind.AARCH64_LDST16_ABS_LO12_NC,
    2: RelocKind.AARCH64_LDST32_ABS_LO12_NC,
    3: RelocKind.AARCH64_LDST64_ABS_LO12_NC,
    4: RelocKind.AARCH64_LDST128_ABS_LO12_NC,
}


def aarch64_branch_reloc(instr_word: int, is_call: bool) -> "RecoveredReloc | None":
    top6 = (instr_word >> 26) & 0x3F
    if is_call and top6 == 0b100101:  # BL
        kind = RelocKind.AARCH64_CALL26
    elif (not is_call) and top6 == 0b000101:  # B
        kind = RelocKind.AARCH64_JUMP26
    else:
        return None
    return RecoveredReloc(offset=0, target_va=0, kind=kind, width=4, trailing=0)


def _is_adr_family(word: int) -> bool:
    return (word >> 24) & 0x1F == 0b10000


def is_adrp(word: int) -> bool:
    """ADRP -- the page-base half of an ADRP/ADD or ADRP/LDR pair."""
    return _is_adr_family(word) and bool(word >> 31)


def adrp_page(word: int, instr_addr: int) -> int:
    """The page ``ADRP`` at ``instr_addr`` materializes."""
    return (instr_addr & _PAGE_MASK) + (get_imm21(word) << 12)


def dest_reg(word: int) -> int:
    return word & 0x1F


def base_reg(word: int) -> int:
    return (word >> 5) & 0x1F


def _is_add_imm(word: int) -> bool:
    # sf 0 0 100010 sh imm12 Rn Rd -- ADD (immediate), 32- or 64-bit, S == 0.
    return (word >> 23) & 0xFF == 0b00100010


def _is_ldst_uimm(word: int) -> bool:
    # size 111 V 01 opc imm12 Rn Rt -- LDR/STR with unsigned immediate offset.
    return (word & 0x3B000000) == 0x39000000


def _is_ldr_literal(word: int) -> bool:
    # opc 011 V 00 imm19 Rt -- LDR (literal).
    return (word & 0x3B000000) == 0x18000000


def aarch64_data_reloc(instr_word: int, instr_addr: int,
                       target_va: int) -> "RecoveredReloc | None":
    """Classify a PC-relative data reference from ``instr_addr`` to ``target_va``.

    Covers the forms Binary Ninja reports a data reference for: ``ADRP`` (page
    base), the ``ADD``/``LDR``/``STR`` that supplies the page offset, ``ADR``,
    and ``LDR`` literal. The instruction's own immediate has to reproduce the
    target -- otherwise the reference belongs to some other instruction in the
    pair and gets no relocation here.

    ``offset`` is 0: the whole 4-byte word is the fixup site.
    """
    if _is_adr_family(instr_word):
        imm = get_imm21(instr_word)
        if instr_word >> 31:  # ADRP
            if (instr_addr & _PAGE_MASK) + (imm << 12) == (target_va & _PAGE_MASK):
                return RecoveredReloc(0, target_va, RelocKind.AARCH64_ADR_PREL_PG_HI21, 4)
            return None
        if instr_addr + imm == target_va:  # ADR
            return RecoveredReloc(0, target_va, RelocKind.AARCH64_ADR_PREL_LO21, 4)
        return None

    if _is_add_imm(instr_word):
        shift = (instr_word >> 22) & 0x1
        if shift == 0 and get_imm12(instr_word) == (target_va & 0xFFF):
            return RecoveredReloc(0, target_va, RelocKind.AARCH64_ADD_ABS_LO12_NC, 4)
        return None

    if _is_ldst_uimm(instr_word):
        scale = ldst_scale(instr_word)
        kind = _LDST_KIND_BY_SCALE.get(scale)
        if kind is not None and (get_imm12(instr_word) << scale) == (target_va & 0xFFF):
            return RecoveredReloc(0, target_va, kind, 4)
        return None

    if _is_ldr_literal(instr_word):
        if instr_addr + get_imm19(instr_word) == target_va:
            return RecoveredReloc(0, target_va, RelocKind.AARCH64_LD_PREL_LO19, 4)
        return None

    return None
