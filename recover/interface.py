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


class FieldClaims:
    """Tracks which byte windows of one instruction already carry a relocation.

    An instruction may legitimately hold more than one relocatable field (an
    x86 ModRM displacement *and* a trailing immediate, say), but two fixups may
    never overlap: the second would patch bytes the first one owns. Candidates
    are offered lowest-offset-first, so the displacement wins over a later
    immediate when a scan matches both at overlapping positions.
    """

    def __init__(self) -> None:
        self._taken: list[tuple[int, int]] = []

    def claim(self, offset: int, width: int) -> bool:
        end = offset + width
        for start, stop in self._taken:
            if offset < stop and start < end:
                return False
        self._taken.append((offset, end))
        return True


def find_pcrel_fields(instr_bytes: bytes, instr_addr: int, instr_len: int,
                      target_va: int) -> "list[tuple[int, int]]":
    """Every 4-byte field whose stored displacement reproduces ``target_va``.

    next_ip is fixed at ``instr_addr + instr_len`` regardless of field position,
    so for each candidate offset o we check ``next_ip + int32(bytes[o:o+4]) ==
    target``. Returns ``(offset, trailing)`` pairs -- where ``trailing =
    instr_len - offset - 4`` -- in ascending offset order. An instruction can
    carry two fields pointing at the same address, and each needs its own
    relocation, so every match is reported rather than one.
    """
    next_ip = instr_addr + instr_len
    out: list[tuple[int, int]] = []
    for o in range(0, len(instr_bytes) - 3):
        disp = int.from_bytes(instr_bytes[o:o + 4], "little", signed=True)
        if next_ip + disp == target_va:
            out.append((o, instr_len - o - 4))
    return out


def find_pcrel_field(instr_bytes: bytes, instr_addr: int, instr_len: int,
                     target_va: int) -> "tuple[int, int] | None":
    """Single best PC-relative field, for callers that want exactly one.

    A branch has one displacement and x86 puts it last, so a match with no
    trailing bytes is preferred; otherwise the latest match wins, which is the
    real displacement rather than a coincidental earlier window.
    """
    matches = find_pcrel_fields(instr_bytes, instr_addr, instr_len, target_va)
    if not matches:
        return None
    for match in matches:
        if match[1] == 0:
            return match
    return matches[-1]


def find_abs_fields(instr_bytes: bytes, target_va: int, width: int) -> "list[int]":
    """Every ``width``-byte window storing ``target_va`` (absolute pointer)."""
    if width <= 0 or width > len(instr_bytes):
        return []
    try:
        needle = target_va.to_bytes(width, "little")
    except OverflowError:
        return []
    out: list[int] = []
    idx = instr_bytes.find(needle)
    while idx >= 0:
        out.append(idx)
        idx = instr_bytes.find(needle, idx + 1)
    return out


def find_abs_field(instr_bytes: bytes, target_va: int, width: int) -> "int | None":
    """First window storing ``target_va``.

    First, not last: where a ModRM displacement and a trailing immediate both
    hold the value, the displacement comes first and is the field the encoding
    puts the address in.
    """
    matches = find_abs_fields(instr_bytes, target_va, width)
    return matches[0] if matches else None
