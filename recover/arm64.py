"""aarch64 branch relocation classification (Binja-free)."""

from __future__ import annotations

from binja_delink.objwrite.relocs import RelocKind
from binja_delink.recover.interface import RecoveredReloc


def aarch64_branch_reloc(instr_word: int, is_call: bool) -> RecoveredReloc | None:
    top6 = (instr_word >> 26) & 0x3F
    if is_call and top6 == 0b100101:  # BL
        kind = RelocKind.AARCH64_CALL26
    elif (not is_call) and top6 == 0b000101:  # B
        kind = RelocKind.AARCH64_JUMP26
    else:
        return None
    return RecoveredReloc(offset=0, target_va=0, kind=kind, width=4, trailing=0)
