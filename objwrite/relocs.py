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
