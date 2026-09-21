"""A whole split, written out and handed to a real linker."""

from __future__ import annotations

import shutil
import struct
import subprocess

import pytest

from binja_delink import emit
from binja_delink.grouping import SymbolDef
from binja_delink.model import Arch, Function, Model, Reloc, Section, SegClass, Symbol
from binja_delink.objwrite.coff import write_coff
from binja_delink.objwrite.elf import write_elf
from binja_delink.objwrite.relocs import RelocKind
from binja_delink.recover.interface import RecoveredReloc
from binja_delink.resolver import SymbolResolver

TEXT = Section("text", 0x1000, 0x1100, True, False, True, SegClass.CODE)
DATA = Section("data", 0x2000, 0x2020, True, True, False, SegClass.DATA)

# caller: call <callee> ; mov rax, [rip+datum] ; ret
CALLER = b"\xe8" + struct.pack("<i", 0x1040 - 0x1005) + b"\x48\x8b\x05" + \
    struct.pack("<i", 0x2000 - 0x100C) + b"\xc3"
CALLEE = b"\x31\xc0\xc3"


def _memory(va: int, length: int) -> "bytes | None":
    blob = bytearray()
    for i in range(length):
        addr = va + i
        if 0x1000 <= addr < 0x1000 + len(CALLER):
            blob.append(CALLER[addr - 0x1000])
        elif 0x1040 <= addr < 0x1040 + len(CALLEE):
            blob.append(CALLEE[addr - 0x1040])
        elif 0x2000 <= addr < 0x2020:
            blob.append(0xAA)
        else:
            blob.append(0)
    return bytes(blob)


def _recover(func, _data):
    if func.start != 0x1000:
        return []
    return [
        RecoveredReloc(1, 0x1040, RelocKind.PCREL32, 4, 0),
        RecoveredReloc(8, 0x2000, RelocKind.PCREL32, 4, 0),
    ]


def _split(fmt: str):
    model = Model(arch=Arch.X86_64, bits=64, little_endian=True, image_base=0x1000,
                  filetype="ELF", input_file="sample",
                  sections=[TEXT, DATA],
                  functions=[Function(0x1000, 0x1000 + len(CALLER), "caller"),
                             Function(0x1040, 0x1040 + len(CALLEE), "callee")],
                  symbols=[Symbol(0x2000, "datum")],
                  relocations=[Reloc(0x2008, "ABS", 8, 0x1040)])
    resolver = SymbolResolver(model, model.relocations)
    groups = {
        "caller.o": {"caller": SymbolDef(0x1000, len(CALLER), "static")},
        "callee.o": {"callee": SymbolDef(0x1040, len(CALLEE), "static")},
    }
    return emit.split(model, resolver, groups, _memory, _recover, fmt)


def test_split_produces_a_complete_set_of_objects():
    images, stats = _split("elf")
    assert [name for name, _image in images] == ["caller.o", "callee.o", "__shared_data.o"]
    assert stats.relocations == 3          # two in caller, one in the data section
    assert stats.unresolved == 0
    # callee is only reachable across an object boundary, so it has to be global.
    callee = dict(images)["callee.o"]
    assert next(s for s in callee.symbols if s.name == "callee").is_global


def test_objects_link(tmp_path):
    linker = shutil.which("ld.lld") or shutil.which("ld")
    if linker is None:
        pytest.skip("no linker available")
    images, _stats = _split("elf")
    paths = []
    for name, image in images:
        path = tmp_path / name
        path.write_bytes(write_elf(image))
        paths.append(str(path))
    out = tmp_path / "linked.o"
    result = subprocess.run([linker, "-r", "-o", str(out), *paths],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

    readelf = shutil.which("llvm-readelf") or shutil.which("readelf")
    if readelf is None:
        pytest.skip("no readelf available")
    symbols = subprocess.run([readelf, "-s", str(out)], capture_output=True, text=True).stdout
    # Everything the objects referenced across the boundary now has a definition.
    for line in symbols.splitlines():
        assert "UND" not in line or "datum" not in line
    assert "callee" in symbols and "caller" in symbols


def test_coff_objects_are_written_too(tmp_path):
    images, _stats = _split("coff")
    assert [name for name, _image in images] == ["caller.obj", "callee.obj", "__shared_data.obj"]
    blob = write_coff(dict(images)["caller.obj"])
    assert struct.unpack_from("<H", blob, 0)[0] == 0x8664      # IMAGE_FILE_MACHINE_AMD64
