"""Object writers: ELF32/REL for i386 and AArch64 immediate encoding (issues #3, #5)."""

from __future__ import annotations

import shutil
import struct
import subprocess

import pytest

from binja_delink.model import Arch
from binja_delink.objwrite.aarch64 import get_imm12, get_imm21, get_imm26, set_imm12, set_imm21
from binja_delink.objwrite.coff import write_coff
from binja_delink.objwrite.elf import write_elf
from binja_delink.objwrite.objfile import (
    ObjectImage, ObjReloc, ObjSection, ObjSectionKind, ObjSymbol,
)
from binja_delink.objwrite.relocs import RelocKind, supported

_ELFCLASS32 = 1
_ELFCLASS64 = 2


def _i386_image() -> ObjectImage:
    image = ObjectImage(arch=Arch.X86)
    # call rel32 ; mov eax, <abs32> ; ret
    image.sections.append(ObjSection(".text", ObjSectionKind.TEXT,
                                     b"\xe8\x00\x00\x00\x00\xb8\x00\x00\x00\x00\xc3"))
    image.sections.append(ObjSection(".data", ObjSectionKind.DATA, b"\xaa" * 16))
    image.symbols.append(ObjSymbol("local_fn", 1, 0, False, True))
    image.symbols.append(ObjSymbol("datum", 2, 4, True, False))
    image.relocs.append(ObjReloc(1, 1, 1, RelocKind.PCREL32, 0, 0))
    image.relocs.append(ObjReloc(1, 6, 1, RelocKind.ABS32, 4, 0))
    return image


def _aarch64_image() -> ObjectImage:
    image = ObjectImage(arch=Arch.AARCH64)
    bl = 0x94000000 | 0x10               # stale displacement from the original image
    adrp = set_imm21(0x90000000, 3)
    add = set_imm12(0x91000000, 0x10)
    image.sections.append(ObjSection(".text", ObjSectionKind.TEXT,
                                     struct.pack("<IIII", bl, adrp, add, 0xD65F03C0)))
    image.sections.append(ObjSection(".data", ObjSectionKind.DATA, b"\xbb" * 32))
    image.symbols.append(ObjSymbol("fn", 1, 0, True, True))
    image.symbols.append(ObjSymbol("datum", 2, 0, True, False))
    image.symbols.append(ObjSymbol("callee", 0, 0, True, False))
    image.relocs.append(ObjReloc(1, 0, 2, RelocKind.AARCH64_CALL26, 0, 0))
    image.relocs.append(ObjReloc(1, 4, 1, RelocKind.AARCH64_ADR_PREL_PG_HI21, 0x10, 0))
    image.relocs.append(ObjReloc(1, 8, 1, RelocKind.AARCH64_ADD_ABS_LO12_NC, 0x10, 0))
    return image


def _text_words(blob: bytes, count: int) -> "list[int]":
    """The first ``count`` instruction words of the object's .text.

    Both writers lay section data out immediately after the header, .text
    first, so the words can be read back without parsing the whole container.
    """
    idx = blob.index(b"\xc0\x03\x5f\xd6") - 4 * (count - 1)   # locate the trailing RET
    return list(struct.unpack_from("<" + "I" * count, blob, idx))


def test_i386_elf_is_elfclass32_with_rel():
    blob = write_elf(_i386_image())
    assert blob[:4] == b"\x7fELF"
    assert blob[4] == _ELFCLASS32
    e_type, e_machine = struct.unpack_from("<HH", blob, 16)
    assert (e_type, e_machine) == (1, 3)                      # ET_REL, EM_386
    e_shoff, = struct.unpack_from("<I", blob, 32)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", blob, 46)
    assert e_shentsize == 40
    names_off, = struct.unpack_from("<I", blob, e_shoff + e_shentsize * e_shstrndx + 16)
    shstr = blob[names_off:]
    types = []
    for i in range(e_shnum):
        name_off, sh_type, _flags, _addr, _off, _size, _link, _info, _align, entsize = \
            struct.unpack_from("<IIIIIIIIII", blob, e_shoff + e_shentsize * i)
        name = shstr[name_off:shstr.index(b"\x00", name_off)].decode()
        types.append((name, sh_type, entsize))
    assert (".rel.text", 9, 8) in types                        # SHT_REL, Elf32_Rel
    assert not any(name.startswith(".rela") for name, _t, _e in types)
    assert (".symtab", 2, 16) in types                         # Elf32_Sym


def test_i386_elf_stores_addends_in_place():
    blob = write_elf(_i386_image())
    text = blob[blob.index(b"\xe8"):][:11]
    # R_386_PC32 addend is biased by the field's distance from next_ip.
    assert struct.unpack_from("<i", text, 1)[0] == -4
    assert struct.unpack_from("<I", text, 6)[0] == 4           # R_386_32 addend


def test_x86_64_elf_stays_elfclass64():
    image = _i386_image()
    image.arch = Arch.X86_64
    image.relocs[1] = ObjReloc(1, 6, 1, RelocKind.ABS32, 4, 0)
    blob = write_elf(image)
    assert blob[4] == _ELFCLASS64
    assert struct.unpack_from("<H", blob, 18)[0] == 62         # EM_X86_64


def test_coff_encodes_aarch64_addends_in_the_instruction():
    blob = write_coff(_aarch64_image())
    bl, adrp, add, _ret = _text_words(blob, 4)
    # COFF has nowhere else to put an addend, and the linker ORs the branch
    # displacement in, so the stale one must be gone.
    assert get_imm26(bl) == 0
    assert get_imm21(adrp) == 0x10
    assert get_imm12(add) == 0x10


def test_elf_clears_aarch64_immediates_because_rela_carries_them():
    blob = write_elf(_aarch64_image())
    bl, adrp, add, _ret = _text_words(blob, 4)
    assert get_imm26(bl) == 0
    assert get_imm21(adrp) == 0
    assert get_imm12(add) == 0


def test_unrepresentable_kinds_are_reported_not_guessed():
    assert supported("elf", Arch.AARCH64, RelocKind.AARCH64_LD_PREL_LO19)
    assert not supported("coff", Arch.AARCH64, RelocKind.AARCH64_LD_PREL_LO19)
    assert not supported("elf", Arch.X86, RelocKind.ABS64)
    with pytest.raises(ValueError):
        supported("mach-o", Arch.X86, RelocKind.ABS32)


@pytest.mark.parametrize("name,blob_fn,args", [
    ("x86.o", lambda: write_elf(_i386_image()), ["-m", "elf_i386"]),
    ("aarch64.o", lambda: write_elf(_aarch64_image()), []),
])
def test_linker_accepts_the_objects(tmp_path, name, blob_fn, args):
    linker = shutil.which("ld.lld") or shutil.which("ld")
    if linker is None:
        pytest.skip("no linker available")
    path = tmp_path / name
    path.write_bytes(blob_fn())
    # ld.lld handles every target; GNU ld needs the emulation spelled out and
    # only knows the one it was built for.
    emulation = [] if linker.endswith("ld.lld") else args
    cmd = [linker, *emulation, "-r", "-o", str(tmp_path / "out.o"), str(path)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
