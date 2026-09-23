"""AArch64 instruction-word immediate fields (Binja-free).

AArch64 keeps a relocation's value inside the instruction word, split across
bitfields, instead of in a flat little-endian field. Both writers need the same
encoding: COFF stores the addend in those bits (the linker adds the symbol
value to whatever it finds there), while ELF RELA carries the addend out of
line and expects the field itself to be clear.
"""

from __future__ import annotations

from binja_delink.objwrite.relocs import RelocKind

_LDST_KINDS = {
    RelocKind.AARCH64_LDST8_ABS_LO12_NC: 0,
    RelocKind.AARCH64_LDST16_ABS_LO12_NC: 1,
    RelocKind.AARCH64_LDST32_ABS_LO12_NC: 2,
    RelocKind.AARCH64_LDST64_ABS_LO12_NC: 3,
    RelocKind.AARCH64_LDST128_ABS_LO12_NC: 4,
}


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def get_imm26(word: int) -> int:
    """Byte displacement of a B/BL."""
    return _sign_extend(word & 0x03FFFFFF, 26) << 2


def set_imm26(word: int, value: int) -> int:
    if value % 4:
        raise ValueError(f"imm26 displacement {value} is not 4-byte aligned")
    scaled = value >> 2
    if not -(1 << 25) <= scaled < (1 << 25):
        raise ValueError(f"imm26 displacement {value} out of range")
    return (word & ~0x03FFFFFF) | (scaled & 0x03FFFFFF)


def get_imm19(word: int) -> int:
    """Byte displacement of an LDR (literal) / conditional branch."""
    return _sign_extend((word >> 5) & 0x7FFFF, 19) << 2


def set_imm19(word: int, value: int) -> int:
    if value % 4:
        raise ValueError(f"imm19 displacement {value} is not 4-byte aligned")
    scaled = value >> 2
    if not -(1 << 18) <= scaled < (1 << 18):
        raise ValueError(f"imm19 displacement {value} out of range")
    return (word & ~(0x7FFFF << 5)) | ((scaled & 0x7FFFF) << 5)


def get_imm21(word: int) -> int:
    """ADR/ADRP immediate, in units of 1 byte (ADR) or 4 KiB pages (ADRP)."""
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    return _sign_extend((immhi << 2) | immlo, 21)


def set_imm21(word: int, value: int) -> int:
    if not -(1 << 20) <= value < (1 << 20):
        raise ValueError(f"imm21 immediate {value} out of range")
    raw = value & 0x1FFFFF
    word &= ~((0x3 << 29) | (0x7FFFF << 5))
    return word | ((raw & 0x3) << 29) | (((raw >> 2) & 0x7FFFF) << 5)


def get_imm12(word: int) -> int:
    """Raw (unscaled) imm12 field of an ADD immediate or LDR/STR unsigned offset."""
    return (word >> 10) & 0xFFF


def set_imm12(word: int, value: int) -> int:
    if not 0 <= value <= 0xFFF:
        raise ValueError(f"imm12 immediate {value} out of range")
    return (word & ~(0xFFF << 10)) | (value << 10)


def ldst_scale(word: int) -> int:
    """log2 of the access size of an LDR/STR with unsigned immediate offset."""
    size = (word >> 30) & 0x3
    # 128-bit SIMD load/store encodes size=0 with opc<1> set.
    if size == 0 and (word & 0x04800000) == 0x04800000:
        return 4
    return size


def addend_representable(kind: RelocKind, addend: int) -> bool:
    """Whether ``addend`` survives a round trip through ``kind``'s field.

    Only COFF needs this: it has nowhere but the instruction to put an addend.
    ELF RELA always carries it out of line.
    """
    try:
        set_addend(0, kind, addend)
    except ValueError:
        return False
    return True


def set_addend(word: int, kind: RelocKind, addend: int) -> int:
    """Clear ``kind``'s immediate field in ``word`` and write ``addend`` into it.

    ``addend`` is always a byte offset; the field's own scaling is applied here.
    Raises ``ValueError`` when the field cannot hold it.
    """
    if kind in (RelocKind.AARCH64_CALL26, RelocKind.AARCH64_JUMP26):
        # COFF BRANCH26 ORs the computed displacement into the word, so the
        # field has to be clear and an addend has nowhere to live.
        if addend:
            raise ValueError(f"branch relocation cannot carry addend {addend}")
        return set_imm26(word, 0)
    if kind in (RelocKind.AARCH64_ADR_PREL_PG_HI21, RelocKind.AARCH64_ADR_PREL_LO21):
        # Byte addend, even for ADRP: the linker adds it before taking the page.
        return set_imm21(word, addend)
    if kind == RelocKind.AARCH64_ADD_ABS_LO12_NC:
        # Only the low 12 bits matter; the page bits ride in the ADRP.
        return set_imm12(word, addend & 0xFFF)
    if kind in _LDST_KINDS:
        scale = ldst_scale(word)
        low = addend & 0xFFF
        if low % (1 << scale):
            raise ValueError(f"addend {addend} is not {1 << scale}-byte aligned for {kind.name}")
        return set_imm12(word, low >> scale)
    if kind == RelocKind.AARCH64_LD_PREL_LO19:
        if addend:
            raise ValueError(f"LD_PREL_LO19 cannot carry addend {addend}")
        return set_imm19(word, 0)
    raise ValueError(f"{kind.name} is not an AArch64 instruction-encoded relocation")
