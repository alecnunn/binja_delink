"""Split orchestration: build ObjectImages from a Model (Binja-free)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from binja_delink.grouping import SymbolDef, retarget_extensions
from binja_delink.model import Arch, Function, Model, SegClass
from binja_delink.objwrite import aarch64
from binja_delink.objwrite.objfile import (
    ObjectImage, ObjReloc, ObjSection, ObjSectionKind, ObjSymbol,
)
from binja_delink.objwrite.relocs import AARCH64_KINDS, RelocKind, supported
from binja_delink.recover.interface import RecoveredReloc
from binja_delink.resolver import SymbolResolver, section_start_symbols

BytesFn = Callable[[int, int], "bytes | None"]
RecoverFn = Callable[[Function, bytes], "list[RecoveredReloc]"]

_SHARED_STEM = "__shared_data"

# Keep a split from logging one line per function on a large binary.
_WARNING_LIMIT = 50


@dataclass
class EmitStats:
    objects: int = 0
    functions: int = 0
    text_bytes: int = 0
    relocations: int = 0
    unresolved: int = 0
    unsupported: int = 0
    skipped_functions: int = 0
    renamed_symbols: int = 0
    promoted_symbols: int = 0
    local_symbols: int = 0
    undef_symbols: int = 0
    warnings: list[str] = field(default_factory=list)
    suppressed_warnings: int = 0

    def warn(self, message: str) -> None:
        if len(self.warnings) < _WARNING_LIMIT:
            self.warnings.append(message)
        else:
            self.suppressed_warnings += 1

    def merge(self, other: "EmitStats") -> None:
        self.objects += other.objects
        self.functions += other.functions
        self.text_bytes += other.text_bytes
        self.relocations += other.relocations
        self.unresolved += other.unresolved
        self.unsupported += other.unsupported
        self.skipped_functions += other.skipped_functions
        self.renamed_symbols += other.renamed_symbols
        self.promoted_symbols += other.promoted_symbols
        self.local_symbols += other.local_symbols
        self.undef_symbols += other.undef_symbols
        for message in other.warnings:
            self.warn(message)
        self.suppressed_warnings += other.suppressed_warnings

    def summary(self) -> str:
        return (f"{self.objects} objects, {self.functions} functions, "
                f"{self.text_bytes} text bytes, {self.relocations} relocations, "
                f"{self.unresolved} unresolved, {self.unsupported} unsupported, "
                f"{self.skipped_functions} skipped functions, "
                f"{self.undef_symbols} undefined symbols, "
                f"{self.promoted_symbols} symbols promoted to global, "
                f"{self.renamed_symbols} renamed symbols")


def _resolve(resolver: SymbolResolver, kind: RelocKind, va: int) -> "tuple[str, int] | None":
    if kind == RelocKind.PCREL32:
        return resolver.resolve_code(va) or resolver.resolve_data(va)
    return resolver.resolve_data(va)


def _emittable(fmt: str, arch: Arch, kind: RelocKind, addend: int) -> "str | None":
    """Reason ``kind`` cannot be written for ``fmt``/``arch``, or None if it can.

    COFF has nowhere to put an AArch64 addend except the instruction's own
    immediate field, so an addend that does not fit there is as unwritable as a
    missing relocation type.
    """
    if not supported(fmt, arch, kind):
        return f"{fmt} has no relocation type for {kind.name} on {arch.value}"
    if fmt == "coff" and kind in AARCH64_KINDS and not aarch64.addend_representable(kind, addend):
        return f"{fmt} cannot encode addend {addend:#x} in a {kind.name} field"
    return None


class _Builder:
    """Accumulates one section's symbols/relocs with two-pass name binding."""

    def __init__(self, arch: Arch) -> None:
        self.image = ObjectImage(arch=arch)
        self._sym_index: dict[str, int] = {}   # name -> symbol list index (defined)
        self._pending: list[tuple[int, int, str, int, RelocKind, int]] = []
        # (section_index, offset, name, addend, kind, trailing)

    def add_section(self, sec: ObjSection) -> int:
        self.image.sections.append(sec)
        return len(self.image.sections)  # 1-based index

    def defines(self, name: str) -> bool:
        return name in self._sym_index

    def unique_name(self, name: str, address: int) -> str:
        """A name not yet defined in this object, derived from ``name``.

        Two definitions of one name in a single object make every relocation
        against that name ambiguous and are rejected outright by some linkers,
        so a collision (static functions sharing a name across translation
        units, say) is disambiguated by address -- deterministically, so
        repeated splits of the same binary agree.
        """
        if not self.defines(name):
            return name
        candidate = f"{name}_{address:x}"
        suffix = 2
        while self.defines(candidate):
            candidate = f"{name}_{address:x}_{suffix}"
            suffix += 1
        return candidate

    def define_symbol(self, name: str, section_index: int, value: int,
                      is_global: bool, is_func: bool) -> int:
        if self.defines(name):
            raise ValueError(f"duplicate definition of symbol {name!r} in one object")
        idx = len(self.image.symbols)
        self.image.symbols.append(ObjSymbol(name, section_index, value, is_global, is_func))
        self._sym_index[name] = idx
        return idx

    def stage_reloc(self, section_index: int, offset: int, name: str,
                    addend: int, kind: RelocKind, trailing: int) -> None:
        self._pending.append((section_index, offset, name, addend, kind, trailing))

    def finish(self) -> "tuple[int, int]":
        undef: dict[str, int] = {}
        for section_index, offset, name, addend, kind, trailing in self._pending:
            if name in self._sym_index:
                sym_idx = self._sym_index[name]
            elif name in undef:
                sym_idx = undef[name]
            else:
                sym_idx = len(self.image.symbols)
                self.image.symbols.append(ObjSymbol(name, 0, 0, True, False))
                undef[name] = sym_idx
            self.image.relocs.append(
                ObjReloc(section_index, offset, sym_idx, kind, addend, trailing))
        return (len(self._sym_index), len(undef))


def read_function_bytes(func: "Function | None", d: SymbolDef,
                        bytes_fn: BytesFn) -> "bytes | None":
    """Bytes emitted for one function: its ranges concatenated, gaps dropped.

    A function Binary Ninja reports as several address ranges (block-reordered
    code) owns only those ranges; the bytes in between belong to other
    functions and must not end up in this object.
    """
    if func is not None and not func.contiguous():
        chunks: list[bytes] = []
        for start, end in func.ranges:
            raw = bytes_fn(start, end - start)
            if raw is None or len(raw) < end - start:
                return None
            chunks.append(bytes(raw[:end - start]))
        return b"".join(chunks)
    raw = bytes_fn(d.address, d.size)
    if raw is None or len(raw) < d.size:
        return None
    return bytes(raw[:d.size])


def build_group_image(model: Model, resolver: SymbolResolver,
                      group_syms: "dict[str, SymbolDef]", bytes_fn: BytesFn,
                      recover_fn: RecoverFn, fmt: str) -> "tuple[ObjectImage, EmitStats]":
    stats = EmitStats(objects=1)
    builder = _Builder(model.arch)
    text_idx = builder.add_section(ObjSection(".text", ObjSectionKind.TEXT, b""))
    text_bytes = bytearray()

    funcs = sorted(
        ((name, d) for name, d in group_syms.items() if d.size > 0),
        key=lambda kv: kv[1].address,
    )
    func_by_start = {f.start: f for f in model.functions}

    for name, d in funcs:
        func = func_by_start.get(d.address)
        raw = read_function_bytes(func, d, bytes_fn)
        if raw is None:
            stats.skipped_functions += 1
            stats.warn(f"{name} at {d.address:#x}: cannot read {d.size} bytes; function "
                       f"omitted, references to it will link as undefined")
            continue
        if func is not None and not func.contiguous() and func.size() != d.size:
            stats.warn(f"{name} at {d.address:#x}: grouping records {d.size} bytes but the "
                       f"function covers {func.size()} bytes in {len(func.ranges)} ranges; "
                       f"emitting the ranges")
        buf = bytearray(raw)
        if func is None:
            func = Function(d.address, d.address + d.size, name)
        fn_off = len(text_bytes)

        for rec in recover_fn(func, bytes(buf)):
            resolved = _resolve(resolver, rec.kind, rec.target_va)
            if resolved is None:
                stats.unresolved += 1
                continue
            sym_name, in_sym_addend = resolved
            reason = _emittable(fmt, model.arch, rec.kind, in_sym_addend)
            if reason is not None:
                stats.unsupported += 1
                stats.warn(f"{name} at {d.address:#x}+{rec.offset:#x} -> {sym_name}: {reason}")
                continue
            w = rec.width
            # AArch64 immediates are split across the instruction word; the
            # writers rewrite those bitfields, so zeroing a flat field here
            # would destroy the opcode.
            if rec.kind not in AARCH64_KINDS:
                if rec.offset + w <= len(buf):
                    buf[rec.offset:rec.offset + w] = b"\x00" * w
            builder.stage_reloc(text_idx, fn_off + rec.offset, sym_name,
                                in_sym_addend, rec.kind, rec.trailing)
            stats.relocations += 1

        text_bytes += buf
        sym_name = builder.unique_name(name, d.address)
        if sym_name != name:
            stats.renamed_symbols += 1
            stats.warn(f"symbol {name!r} is defined twice in one object; the definition at "
                       f"{d.address:#x} was renamed to {sym_name!r} (references to {name!r} "
                       f"still bind to the first definition)")
        builder.define_symbol(sym_name, text_idx, fn_off + func.entry_offset(),
                              d.scope == "global", True)
        stats.functions += 1
        stats.text_bytes += len(buf)

    builder.image.sections[text_idx - 1] = ObjSection(".text", ObjSectionKind.TEXT, bytes(text_bytes))
    stats.local_symbols, stats.undef_symbols = builder.finish()
    return (builder.image, stats)


def emit_shared(model: Model, resolver: SymbolResolver,
                bytes_fn: BytesFn) -> "tuple[ObjectImage, EmitStats]":
    stats = EmitStats(objects=1)
    builder = _Builder(model.arch)
    class_meta = {
        SegClass.DATA: (ObjSectionKind.DATA, ".data"),
        SegClass.CONST: (ObjSectionKind.RDATA, ".rdata"),
        SegClass.BSS: (ObjSectionKind.BSS, ".bss"),
    }
    # One start symbol per section, not per class: see section_start_symbols.
    start_symbols = section_start_symbols(model.sections)

    for sec in model.sections:
        if sec.seg_class not in class_meta:
            continue
        kind, sec_name = class_meta[sec.seg_class]
        if kind == ObjSectionKind.BSS:
            sidx = builder.add_section(ObjSection(sec_name, kind, b"", bss_size=sec.size()))
        else:
            raw = bytes_fn(sec.start, sec.size()) or bytes(sec.size())
            buf = bytearray(raw)
            data_relocs: list[tuple[int, str, int, RelocKind]] = []
            for r in resolver.relocs_in(sec.start, sec.end):
                w = r.size
                off = r.addr - sec.start
                if off + w > len(buf):
                    stats.unsupported += 1
                    stats.warn(f"{sec_name}: relocation at {r.addr:#x} ({w} bytes) runs past "
                               f"the section; dropped")
                    continue
                if w not in (4, 8):
                    stats.unsupported += 1
                    stats.warn(f"{sec_name}: relocation at {r.addr:#x} has unsupported width "
                               f"{w}; dropped")
                    continue
                resolved = resolver.resolve_data(r.target)
                if resolved is None:
                    stats.unresolved += 1
                    stats.warn(f"{sec_name}: relocation at {r.addr:#x} targets {r.target:#x}, "
                               f"which is in no known section or symbol; dropped")
                    continue
                sym_name, addend = resolved
                buf[off:off + w] = b"\x00" * w
                kind_r = RelocKind.ABS64 if w == 8 else RelocKind.ABS32
                # Reloc.target is the final address the fixup must point at
                # (Binary Ninja has already folded in any stored addend), so
                # the in-symbol offset from the resolver is the whole addend.
                data_relocs.append((off, sym_name, addend, kind_r))
            sidx = builder.add_section(ObjSection(sec_name, kind, bytes(buf)))
            for off, sym_name, addend, kind_r in data_relocs:
                builder.stage_reloc(sidx, off, sym_name, addend, kind_r, 0)
                stats.relocations += 1

        start_sym = start_symbols.get(sec.start)
        if start_sym is not None and not builder.defines(start_sym):
            builder.define_symbol(start_sym, sidx, 0, True, False)

        for va, var in list(resolver.variables.items()):
            if sec.contains(va):
                name = builder.unique_name(var.name, va)
                if name != var.name:
                    stats.renamed_symbols += 1
                    stats.warn(f"variable {var.name!r} is defined twice in the shared object; "
                               f"the one at {va:#x} was renamed to {name!r}")
                builder.define_symbol(name, sidx, va - sec.start, var.public, False)

    stats.local_symbols, stats.undef_symbols = builder.finish()
    return (builder.image, stats)


def promote_cross_object_symbols(images: "list[tuple[str, ObjectImage]]",
                                 stats: EmitStats) -> None:
    """Make every definition that another object references global.

    Visibility cannot be read off the input binary: Binary Ninja's PE view, for
    one, gives ordinary functions ``LocalBinding`` whether they were static or
    not. But it follows from the split itself -- a name some *other* object
    emits as an undefined external has to be a global definition here, or the
    link fails.
    """
    referenced: set[str] = set()
    for _filename, image in images:
        for sym in image.symbols:
            if sym.section_index == 0:
                referenced.add(sym.name)
    for _filename, image in images:
        for sym in image.symbols:
            if sym.section_index != 0 and not sym.is_global and sym.name in referenced:
                sym.is_global = True
                stats.promoted_symbols += 1


def warn_duplicate_definitions(images: "list[tuple[str, ObjectImage]]",
                               stats: EmitStats) -> None:
    """Warn when one name is defined, visibly, by more than one object.

    Within an object a collision is renamed away, but two objects can still
    define the same name -- same-named statics in different translation units,
    typically -- and once both are visible to the linker the link fails on a
    duplicate symbol. The grouping file cannot express the difference, so this
    is reported rather than silently patched.
    """
    owners: dict[str, list[str]] = {}
    for filename, image in images:
        for sym in image.symbols:
            if sym.section_index != 0 and sym.is_global:
                owners.setdefault(sym.name, []).append(filename)
    for name, files in sorted(owners.items()):
        if len(files) < 2:
            continue
        shown = sorted(files)
        where = ", ".join(shown[:3])
        if len(shown) > 3:
            where += f", and {len(shown) - 3} more"
        stats.warn(f"symbol {name!r} is defined globally by {where}; the link will reject "
                   f"the duplicate")


def split(model: Model, resolver: SymbolResolver, groups: "dict[str, dict[str, SymbolDef]]",
          bytes_fn: BytesFn, recover_fn: RecoverFn,
          fmt: str) -> "tuple[list[tuple[str, ObjectImage]], EmitStats]":
    if fmt not in ("coff", "elf"):
        raise ValueError(f"unknown output format {fmt!r}; expected 'coff' or 'elf'")
    ext = "obj" if fmt == "coff" else "o"
    stats = EmitStats()
    # The grouping file baked in whichever extension was current when it was
    # written; the objects being written now are in the requested format.
    groups, renames = retarget_extensions(groups, ext)
    for message in renames:
        stats.warn(message)

    out: list[tuple[str, ObjectImage]] = []
    for filename, syms in groups.items():
        image, group_stats = build_group_image(model, resolver, syms, bytes_fn, recover_fn, fmt)
        stats.merge(group_stats)
        out.append((filename, image))
    shared_image, shared_stats = emit_shared(model, resolver, bytes_fn)
    stats.merge(shared_stats)
    out.append((f"{_SHARED_STEM}.{ext}", shared_image))
    promote_cross_object_symbols(out, stats)
    warn_duplicate_definitions(out, stats)
    return (out, stats)
