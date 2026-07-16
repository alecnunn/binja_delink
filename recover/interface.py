"""Decoder-free field location for relocation recovery (Binja-free)."""

from __future__ import annotations

from dataclasses import dataclass

from binja_delink.objwrite.relocs import RelocKind


@dataclass(frozen=True)
class RecoveredReloc:
    offset: int       # offset within the function bytes
    target_va: int
    kind: RelocKind
    width: int
    trailing: int = 0


def find_pcrel_field(instr_bytes: bytes, instr_addr: int, instr_len: int,
                     target_va: int) -> tuple[int, int] | None:
    """Find the 4-byte field whose stored disp reproduces target_va.

    next_ip is fixed at instr_addr + instr_len regardless of field position, so
    for each candidate offset o we check next_ip + int32(bytes[o:o+4]) == target.
    Returns (offset, trailing) where trailing = instr_len - o - 4. Prefers the
    latest matching offset (the real displacement rather than a coincidental one).
    """
    next_ip = instr_addr + instr_len
    best: tuple[int, int] | None = None
    for o in range(0, len(instr_bytes) - 3):
        disp = int.from_bytes(instr_bytes[o:o + 4], "little", signed=True)
        if next_ip + disp == target_va:
            best = (o, instr_len - o - 4)
    return best


def find_abs_field(instr_bytes: bytes, target_va: int, width: int) -> int | None:
    """Find the width-byte window storing target_va (absolute pointer)."""
    needle = target_va.to_bytes(width, "little")
    idx = instr_bytes.rfind(needle)
    return idx if idx >= 0 else None
