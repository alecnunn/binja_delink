"""Minimal 64-bit little-endian ELF ET_REL writer with RELA relocations."""

from __future__ import annotations

import struct

from binja_delink.objwrite.objfile import ObjectImage, ObjSectionKind
from binja_delink.objwrite.relocs import RelocKind, elf_machine, elf_reloc_type

_SHT_PROGBITS = 1
_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHT_RELA = 4
_SHT_NOBITS = 8

_SHF_WRITE = 0x1
_SHF_ALLOC = 0x2
_SHF_EXEC = 0x4
_SHF_INFO_LINK = 0x40

_STB_LOCAL = 0
_STB_GLOBAL = 1
_STT_FUNC = 2
_STT_OBJECT = 1
_STT_NOTYPE = 0

_SECTION_FLAGS = {
    ObjSectionKind.TEXT: (_SHT_PROGBITS, _SHF_ALLOC | _SHF_EXEC),
    ObjSectionKind.DATA: (_SHT_PROGBITS, _SHF_ALLOC | _SHF_WRITE),
    ObjSectionKind.RDATA: (_SHT_PROGBITS, _SHF_ALLOC),
    ObjSectionKind.BSS: (_SHT_NOBITS, _SHF_ALLOC | _SHF_WRITE),
}


class _StrTab:
    def __init__(self) -> None:
        self._buf = bytearray(b"\x00")
        self._map: dict[str, int] = {"": 0}

    def add(self, s: str) -> int:
        if s in self._map:
            return self._map[s]
        off = len(self._buf)
        self._buf.extend(s.encode("utf-8") + b"\x00")
        self._map[s] = off
        return off

    def data(self) -> bytes:
        return bytes(self._buf)


def _pcrel_addend(addend: int, trailing: int) -> int:
    return addend - 4 - trailing


class _Sec:
    def __init__(
        self,
        name: str,
        sh_type: int,
        flags: int,
        data: bytes,
        link: int = 0,
        info: int = 0,
        entsize: int = 0,
        addralign: int = 1,
        size_override: int | None = None,
    ) -> None:
        self.name = name
        self.sh_type = sh_type
        self.flags = flags
        self.data = data
        self.link = link
        self.info = info
        self.entsize = entsize
        self.addralign = addralign
        self.size_override = size_override


def write_elf(image: ObjectImage) -> bytes:
    arch = image.arch

    shstr = _StrTab()
    strtab = _StrTab()

    # ObjSection index i (1-based) -> ELF section index i (section 0 is null,
    # then the image sections follow in order at indices 1..N).
    elf_index_of_obj = {i + 1: i + 1 for i in range(len(image.sections))}

    # Symbols: ELF requires local symbols before global symbols in .symtab.
    # Index 0 is reserved for the null symbol.
    ordered = list(enumerate(image.symbols))
    locals_ = [p for p in ordered if not p[1].is_global and p[1].section_index != 0]
    globals_ = [p for p in ordered if p[1].is_global or p[1].section_index == 0]
    sym_order = locals_ + globals_
    # Map original symbol index -> ELF symbol table index (1-based; 0 is null).
    sym_elf_index: dict[int, int] = {}
    for new_i, (orig_i, _sym) in enumerate(sym_order, start=1):
        sym_elf_index[orig_i] = new_i

    # Build .symtab.
    symtab = bytearray(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))  # null symbol
    first_global = 1 + len(locals_)
    for orig_i, sym in sym_order:
        name_off = strtab.add(sym.name)
        if sym.section_index == 0:
            bind, shndx, value = _STB_GLOBAL, 0, 0
        else:
            bind = _STB_GLOBAL if sym.is_global else _STB_LOCAL
            shndx = elf_index_of_obj[sym.section_index]
            value = sym.value
        typ = _STT_FUNC if sym.is_func else (_STT_NOTYPE if sym.section_index == 0 else _STT_OBJECT)
        info = (bind << 4) | typ
        symtab += struct.pack("<IBBHQQ", name_off, info, 0, shndx, value, 0)

    # Assemble section list: null, then image sections, then .symtab,
    # .strtab, one .rela.<name> per relocated section, and .shstrtab last.
    secs: list[_Sec] = [_Sec("", 0, 0, b"")]  # null section
    for sec in image.sections:
        sh_type, flags = _SECTION_FLAGS[sec.kind]
        if sec.kind == ObjSectionKind.BSS:
            secs.append(_Sec(sec.name, sh_type, flags, b"", addralign=16, size_override=sec.bss_size))
        else:
            secs.append(_Sec(sec.name, sh_type, flags, sec.data, addralign=16))

    symtab_index = len(secs)
    strtab_index = symtab_index + 1
    secs.append(
        _Sec(
            ".symtab", _SHT_SYMTAB, 0, bytes(symtab),
            link=strtab_index, info=first_global, entsize=24, addralign=8,
        )
    )
    secs.append(_Sec(".strtab", _SHT_STRTAB, 0, strtab.data(), addralign=1))

    # One .rela.<section> per relocated image section.
    reloc_by_section: dict[int, list] = {}
    for r in image.relocs:
        reloc_by_section.setdefault(r.section_index, []).append(r)
    for obj_sec_index, rs in sorted(reloc_by_section.items()):
        blob = bytearray()
        for r in rs:
            elf_sym = sym_elf_index[r.symbol_index]
            rtype = elf_reloc_type(arch, r.kind)
            addend = _pcrel_addend(r.addend, r.trailing) if r.kind == RelocKind.PCREL32 else r.addend
            r_info = (elf_sym << 32) | rtype
            blob += struct.pack("<QQq", r.offset, r_info, addend)
        target_name = image.sections[obj_sec_index - 1].name
        secs.append(
            _Sec(
                ".rela" + target_name, _SHT_RELA, _SHF_INFO_LINK, bytes(blob),
                link=symtab_index, info=elf_index_of_obj[obj_sec_index],
                entsize=24, addralign=8,
            )
        )

    # shstrtab last; every section name (including its own) must be
    # registered before section headers are written so name offsets are stable.
    shstrtab_index = len(secs)
    for s in secs:
        shstr.add(s.name)
    secs.append(_Sec(".shstrtab", _SHT_STRTAB, 0, b"", addralign=1))
    shstr.add(".shstrtab")
    secs[shstrtab_index].data = shstr.data()

    # Lay out: ELF header (64 bytes) + no program headers, then section
    # data (each aligned per its sh_addralign), then the section header table.
    ehsize = 64
    shentsize = 64
    offset = ehsize
    data_offsets: list[int] = []
    for s in secs:
        if s.sh_type == _SHT_NOBITS or s.name == "":
            data_offsets.append(offset)
            continue
        align = s.addralign if s.addralign else 1
        if offset % align:
            offset += align - (offset % align)
        data_offsets.append(offset)
        offset += len(s.data)
    if offset % 8:
        offset += 8 - (offset % 8)
    shoff = offset

    out = bytearray()
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    out += e_ident
    out += struct.pack(
        "<HHIQQQIHHHHHH",
        1,                    # e_type = ET_REL
        elf_machine(arch),
        1,                    # e_version
        0,                    # e_entry
        0,                    # e_phoff
        shoff,
        0,                    # e_flags
        ehsize,
        0, 0,                 # e_phentsize, e_phnum
        shentsize,
        len(secs),
        shstrtab_index,       # e_shstrndx
    )

    # Section data.
    for i, s in enumerate(secs):
        if s.sh_type == _SHT_NOBITS or s.name == "":
            continue
        if len(out) < data_offsets[i]:
            out += b"\x00" * (data_offsets[i] - len(out))
        out += s.data
    if len(out) < shoff:
        out += b"\x00" * (shoff - len(out))

    # Section headers.
    for i, s in enumerate(secs):
        name_off = shstr.add(s.name)
        size = s.size_override if s.size_override is not None else len(s.data)
        sh_offset = 0 if s.name == "" else data_offsets[i]
        out += struct.pack(
            "<IIQQQQIIQQ",
            name_off,
            s.sh_type,
            s.flags,
            0,           # sh_addr
            sh_offset,
            size,
            s.link,
            s.info,
            s.addralign,
            s.entsize,
        )
    return bytes(out)
