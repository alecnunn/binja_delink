"""Normalized relocation kinds and per-(format, arch) type tables."""

from __future__ import annotations

from enum import Enum, auto

from binja_delink.model import Arch


class RelocKind(Enum):
    PCREL32 = auto()
    ABS32 = auto()
    ABS64 = auto()
    AARCH64_CALL26 = auto()
    AARCH64_JUMP26 = auto()
    # AArch64 PC-relative data addressing. The immediate of each of these is
    # split across instruction-word bitfields, so the writers encode addends
    # through objwrite.aarch64 rather than into a flat little-endian field.
    AARCH64_ADR_PREL_PG_HI21 = auto()   # ADRP page base
    AARCH64_ADR_PREL_LO21 = auto()      # ADR
    AARCH64_ADD_ABS_LO12_NC = auto()    # ADD immediate (page offset)
    AARCH64_LDST8_ABS_LO12_NC = auto()
    AARCH64_LDST16_ABS_LO12_NC = auto()
    AARCH64_LDST32_ABS_LO12_NC = auto()
    AARCH64_LDST64_ABS_LO12_NC = auto()
    AARCH64_LDST128_ABS_LO12_NC = auto()
    AARCH64_LD_PREL_LO19 = auto()       # LDR literal


AARCH64_KINDS = (
    RelocKind.AARCH64_CALL26,
    RelocKind.AARCH64_JUMP26,
    RelocKind.AARCH64_ADR_PREL_PG_HI21,
    RelocKind.AARCH64_ADR_PREL_LO21,
    RelocKind.AARCH64_ADD_ABS_LO12_NC,
    RelocKind.AARCH64_LDST8_ABS_LO12_NC,
    RelocKind.AARCH64_LDST16_ABS_LO12_NC,
    RelocKind.AARCH64_LDST32_ABS_LO12_NC,
    RelocKind.AARCH64_LDST64_ABS_LO12_NC,
    RelocKind.AARCH64_LDST128_ABS_LO12_NC,
    RelocKind.AARCH64_LD_PREL_LO19,
)

# COFF machine numbers.
_COFF_MACHINE: dict[Arch, int] = {Arch.X86: 0x014C, Arch.X86_64: 0x8664, Arch.AARCH64: 0xAA64}
# ELF e_machine.
_ELF_MACHINE: dict[Arch, int] = {Arch.X86: 3, Arch.X86_64: 62, Arch.AARCH64: 183}

# COFF relocation type numbers (non-REL32 kinds; REL32/REL32_N handled below).
_COFF_TYPES: dict[tuple[Arch, RelocKind], int] = {
    (Arch.X86_64, RelocKind.ABS64): 0x0001,   # IMAGE_REL_AMD64_ADDR64
    (Arch.X86_64, RelocKind.ABS32): 0x0002,   # IMAGE_REL_AMD64_ADDR32
    (Arch.X86, RelocKind.ABS32): 0x0006,      # IMAGE_REL_I386_DIR32
    (Arch.X86, RelocKind.PCREL32): 0x0014,    # IMAGE_REL_I386_REL32
    (Arch.AARCH64, RelocKind.AARCH64_CALL26): 0x0003,  # IMAGE_REL_ARM64_BRANCH26
    (Arch.AARCH64, RelocKind.AARCH64_JUMP26): 0x0003,  # BRANCH26 (same as call)
    (Arch.AARCH64, RelocKind.ABS64): 0x000E,  # IMAGE_REL_ARM64_ADDR64
    # IMAGE_REL_ARM64_PAGEBASE_REL21 / REL21 / PAGEOFFSET_12A / PAGEOFFSET_12L.
    (Arch.AARCH64, RelocKind.AARCH64_ADR_PREL_PG_HI21): 0x0004,
    (Arch.AARCH64, RelocKind.AARCH64_ADR_PREL_LO21): 0x0005,
    (Arch.AARCH64, RelocKind.AARCH64_ADD_ABS_LO12_NC): 0x0006,
    (Arch.AARCH64, RelocKind.AARCH64_LDST8_ABS_LO12_NC): 0x0007,
    (Arch.AARCH64, RelocKind.AARCH64_LDST16_ABS_LO12_NC): 0x0007,
    (Arch.AARCH64, RelocKind.AARCH64_LDST32_ABS_LO12_NC): 0x0007,
    (Arch.AARCH64, RelocKind.AARCH64_LDST64_ABS_LO12_NC): 0x0007,
    (Arch.AARCH64, RelocKind.AARCH64_LDST128_ABS_LO12_NC): 0x0007,
    # LDR-literal (R_AARCH64_LD_PREL_LO19) has no COFF counterpart:
    # IMAGE_REL_ARM64_BRANCH19 applies to conditional branches, not loads.
}

# ELF relocation types.
_ELF_TYPES: dict[tuple[Arch, RelocKind], int] = {
    (Arch.X86_64, RelocKind.PCREL32): 2,   # R_X86_64_PC32
    (Arch.X86_64, RelocKind.ABS64): 1,     # R_X86_64_64
    (Arch.X86_64, RelocKind.ABS32): 10,    # R_X86_64_32
    (Arch.X86, RelocKind.PCREL32): 2,      # R_386_PC32
    (Arch.X86, RelocKind.ABS32): 1,        # R_386_32
    (Arch.AARCH64, RelocKind.AARCH64_CALL26): 283,  # R_AARCH64_CALL26
    (Arch.AARCH64, RelocKind.AARCH64_JUMP26): 282,  # R_AARCH64_JUMP26
    (Arch.AARCH64, RelocKind.ABS64): 257,           # R_AARCH64_ABS64
    (Arch.AARCH64, RelocKind.AARCH64_LD_PREL_LO19): 273,
    (Arch.AARCH64, RelocKind.AARCH64_ADR_PREL_LO21): 274,
    (Arch.AARCH64, RelocKind.AARCH64_ADR_PREL_PG_HI21): 275,
    (Arch.AARCH64, RelocKind.AARCH64_ADD_ABS_LO12_NC): 277,
    (Arch.AARCH64, RelocKind.AARCH64_LDST8_ABS_LO12_NC): 278,
    (Arch.AARCH64, RelocKind.AARCH64_LDST16_ABS_LO12_NC): 284,
    (Arch.AARCH64, RelocKind.AARCH64_LDST32_ABS_LO12_NC): 285,
    (Arch.AARCH64, RelocKind.AARCH64_LDST64_ABS_LO12_NC): 286,
    (Arch.AARCH64, RelocKind.AARCH64_LDST128_ABS_LO12_NC): 299,
}


def coff_machine(arch: Arch) -> int:
    return _COFF_MACHINE[arch]


def elf_machine(arch: Arch) -> int:
    return _ELF_MACHINE[arch]


def coff_reloc_type(arch: Arch, kind: RelocKind, trailing: int) -> int:
    if arch == Arch.X86_64 and kind == RelocKind.PCREL32:
        # IMAGE_REL_AMD64_REL32 (0x04) .. REL32_5 (0x09), selected by trailing bytes.
        if trailing < 0 or trailing > 5:
            raise KeyError(f"AMD64 REL32 trailing {trailing} out of range")
        return 0x0004 + trailing
    return _COFF_TYPES[(arch, kind)]


def elf_reloc_type(arch: Arch, kind: RelocKind) -> int:
    return _ELF_TYPES[(arch, kind)]


def supported(fmt: str, arch: Arch, kind: RelocKind) -> bool:
    """Whether ``fmt`` ("coff" or "elf") can represent ``kind`` on ``arch``.

    Callers use this to drop a recovered relocation (with a counted warning)
    instead of failing the whole object at write time.
    """
    if fmt == "coff":
        if arch == Arch.X86_64 and kind == RelocKind.PCREL32:
            return True
        return (arch, kind) in _COFF_TYPES
    if fmt == "elf":
        return (arch, kind) in _ELF_TYPES
    raise ValueError(f"unknown output format {fmt!r}; expected 'coff' or 'elf'")
