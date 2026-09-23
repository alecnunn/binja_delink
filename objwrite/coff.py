"""Minimal COFF object writer (Binja-free)."""

from __future__ import annotations

import struct

from binja_delink.model import Arch
from binja_delink.objwrite import aarch64
from binja_delink.objwrite.objfile import (
    ObjectImage, ObjSectionKind,
)
from binja_delink.objwrite.relocs import (
    AARCH64_KINDS, RelocKind, coff_machine, coff_reloc_type,
)

# Section characteristics.
_SCN_CNT_CODE = 0x00000020
_SCN_CNT_INIT = 0x00000040
_SCN_CNT_UNINIT = 0x00000080
_SCN_ALIGN_16 = 0x00500000
_SCN_MEM_EXEC = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000

_SYM_CLASS_EXTERNAL = 2
_SYM_CLASS_STATIC = 3
_SYM_DTYPE_FUNCTION = 0x20  # complex type FUNCTION in the high nibble

_SECTION_META = {
    ObjSectionKind.TEXT: (".text", _SCN_CNT_CODE | _SCN_MEM_EXEC | _SCN_MEM_READ | _SCN_ALIGN_16),
    ObjSectionKind.DATA: (".data", _SCN_CNT_INIT | _SCN_MEM_READ | _SCN_MEM_WRITE | _SCN_ALIGN_16),
    ObjSectionKind.RDATA: (".rdata", _SCN_CNT_INIT | _SCN_MEM_READ | _SCN_ALIGN_16),
    ObjSectionKind.BSS: (".bss", _SCN_CNT_UNINIT | _SCN_MEM_READ | _SCN_MEM_WRITE | _SCN_ALIGN_16),
}


def _reloc_width(kind: RelocKind) -> int:
    if kind == RelocKind.ABS64:
        return 8
    if kind in (RelocKind.AARCH64_CALL26, RelocKind.AARCH64_JUMP26):
        return 4
    return 4


def _mangle(arch: Arch, name: str) -> str:
    return "_" + name if arch == Arch.X86 else name


def write_coff(image: ObjectImage) -> bytes:
    arch = image.arch
    sections = image.sections

    # Patch addends into section bytes (COFF stores addends in-place).
    patched: list[bytearray] = [bytearray(s.data) for s in sections]
    for r in image.relocs:
        buf = patched[r.section_index - 1]
        w = _reloc_width(r.kind)
        if r.offset + w > len(buf):
            raise ValueError(
                f"reloc offset {r.offset}+{w} exceeds section {r.section_index} size {len(buf)}")
        if r.kind in AARCH64_KINDS:
            # The immediate is split across instruction-word bitfields, and the
            # linker adds the symbol to whatever those bits hold -- so the old
            # displacement has to go and the addend has to be encoded there.
            word = struct.unpack_from("<I", buf, r.offset)[0]
            struct.pack_into("<I", buf, r.offset,
                             aarch64.set_addend(word, r.kind, r.addend) & 0xFFFFFFFF)
            continue
        mask = (1 << (w * 8)) - 1
        struct.pack_into("<I" if w == 4 else "<Q", buf, r.offset, r.addend & mask)

    # String table (names > 8 bytes go here).
    strtab = bytearray(b"\x00\x00\x00\x00")  # placeholder for size, filled at end

    def store_name(name: str) -> bytes:
        raw = name.encode("utf-8")
        if len(raw) <= 8:
            return raw + b"\x00" * (8 - len(raw))
        offset = len(strtab)
        strtab.extend(raw + b"\x00")
        return struct.pack("<II", 0, offset)

    num_sections = len(sections)
    header_size = 20
    sechdr_size = 40
    data_start = header_size + sechdr_size * num_sections

    # Lay out raw section data and per-section relocation blocks.
    raw_blobs: list[bytes] = []
    raw_offsets: list[int] = []
    cursor = data_start
    for i, sec in enumerate(sections):
        if sec.kind == ObjSectionKind.BSS:
            raw_offsets.append(0)
            raw_blobs.append(b"")
        else:
            raw_offsets.append(cursor)
            raw_blobs.append(bytes(patched[i]))
            cursor += len(raw_blobs[-1])

    reloc_by_section: dict[int, list] = {i: [] for i in range(1, num_sections + 1)}
    for r in image.relocs:
        reloc_by_section[r.section_index].append(r)

    reloc_offsets: list[int] = [0] * num_sections
    reloc_blobs: list[bytes] = [b""] * num_sections
    for i in range(num_sections):
        rs = reloc_by_section[i + 1]
        if not rs:
            continue
        reloc_offsets[i] = cursor
        blob = bytearray()
        for r in rs:
            typ = coff_reloc_type(arch, r.kind, r.trailing)
            blob += struct.pack("<IIH", r.offset, r.symbol_index, typ)
        reloc_blobs[i] = bytes(blob)
        cursor += len(reloc_blobs[i])

    symtab_offset = cursor

    # Section headers.
    sechdrs = bytearray()
    for i, sec in enumerate(sections):
        name, chars = _SECTION_META[sec.kind]
        raw_size = sec.bss_size if sec.kind == ObjSectionKind.BSS else len(raw_blobs[i])
        name_field = name.encode("utf-8")[:8]
        name_field += b"\x00" * (8 - len(name_field))
        nrel = len(reloc_by_section[i + 1])
        sechdrs += struct.pack(
            "<8sIIIIIIHHI",
            name_field,
            0,                 # VirtualSize
            0,                 # VirtualAddress
            raw_size,          # SizeOfRawData
            raw_offsets[i],    # PointerToRawData
            reloc_offsets[i],  # PointerToRelocations
            0,                 # PointerToLinenumbers
            nrel,              # NumberOfRelocations
            0,                 # NumberOfLinenumbers
            chars,
        )

    # Symbol table.
    symtab = bytearray()
    for sym in image.symbols:
        name_field = store_name(_mangle(arch, sym.name))
        storage = _SYM_CLASS_EXTERNAL if (sym.is_global or sym.section_index == 0) else _SYM_CLASS_STATIC
        typ = _SYM_DTYPE_FUNCTION if sym.is_func else 0
        symtab += struct.pack(
            "<8sIHHBB",
            name_field,
            sym.value,
            sym.section_index,  # 0 = undefined (IMAGE_SYM_UNDEFINED)
            typ,
            storage,
            0,                  # NumberOfAuxSymbols
        )

    struct.pack_into("<I", strtab, 0, len(strtab))

    file_header = struct.pack(
        "<HHIIIHH",
        coff_machine(arch),
        num_sections,
        0,                       # TimeDateStamp
        symtab_offset,
        len(image.symbols),
        0,                       # SizeOfOptionalHeader
        0,                       # Characteristics
    )

    out = bytearray()
    out += file_header
    out += sechdrs
    for i in range(num_sections):
        out += raw_blobs[i]
    for i in range(num_sections):
        out += reloc_blobs[i]
    out += symtab
    out += strtab
    return bytes(out)
