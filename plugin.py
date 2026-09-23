"""Binary Ninja UI wiring for binja_delink.

This module imports ``binaryninja`` at module scope: it is UI glue and is
only ever imported from inside Binary Ninja (see ``binja_delink/__init__.py``,
which wraps the ``import binaryninja`` probe in try/except and only imports
this module when that probe succeeds).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import binaryninja
from binaryninja import BackgroundTaskThread, BinaryView, PluginCommand, Settings, interaction

from binja_delink import binja_adapter, components, emit, grouping
from binja_delink.model import Arch
from binja_delink.objwrite.coff import write_coff
from binja_delink.objwrite.elf import write_elf
from binja_delink.resolver import SymbolResolver

if TYPE_CHECKING:
    from binja_delink.model import Model

_SETTINGS_GROUP = "delink"

_registered = False


def _pick_format(bv: BinaryView) -> str:
    override = Settings().get_string("delink.outputFormat", bv)
    if override in ("coff", "elf"):
        return override
    vt = str(bv.view_type).lower()
    return "elf" if ("elf" in vt or "mach" in vt) else "coff"


def _build_groups(bv: BinaryView, ext: str) -> "tuple[Model, dict]":
    """Return (model, groups): Components-driven grouping if any component
    exists, else the default one-object-per-function grouping."""
    model = binja_adapter.build_model(bv)
    comp_map = components.read_component_map(bv)
    groups = (components.groups_from_component_map(comp_map, model, ext)
              if comp_map else grouping.generate_default(model, ext))
    return model, groups


def run_split(bv: BinaryView, out_dir: str, fmt: str) -> str:
    """Split the analyzed image into object files under ``out_dir``.

    Usable headlessly (no UI dependency beyond the ``BinaryView`` itself).
    """
    if fmt not in ("coff", "elf"):
        raise ValueError(f"unknown output format {fmt!r}; expected 'coff' or 'elf'")

    ext = "obj" if fmt == "coff" else "o"
    model, groups = _build_groups(bv, ext)
    if model.arch == Arch.OTHER:
        binaryninja.log_warn(f"delink: no field locator for {bv.arch}; absolute-only output")
    resolver = SymbolResolver(model, model.relocations)
    bytes_fn = binja_adapter.make_bytes_fn(bv)
    recover_fn = binja_adapter.make_recover_fn(bv, model)

    # Write the grouping with the extensions the objects will actually use, so
    # the JSON left next to them describes what was written.
    groups, renames = grouping.retarget_extensions(groups, ext)
    for message in renames:
        binaryninja.log_warn(f"delink: {message}")

    os.makedirs(out_dir, exist_ok=True)
    grouping.save(groups, os.path.join(out_dir, grouping.CONFIG_FILENAME))

    writer = write_coff if fmt == "coff" else write_elf
    images, stats = emit.split(model, resolver, groups, bytes_fn, recover_fn, fmt)
    for filename, image in images:
        with open(os.path.join(out_dir, filename), "wb") as fh:
            fh.write(writer(image))

    # Anything dropped along the way changes how the output links, so it is
    # reported rather than counted silently.
    for message in stats.warnings:
        binaryninja.log_warn(f"delink: {message}")
    if stats.suppressed_warnings:
        binaryninja.log_warn(f"delink: {stats.suppressed_warnings} further warnings suppressed")
    return f"delink: wrote {len(images)} objects to {out_dir} ({stats.summary()})"


class _SplitTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, out_dir: str, fmt: str) -> None:
        super().__init__("delink: splitting to objects", can_cancel=True)
        self._bv = bv
        self._out_dir = out_dir
        self._fmt = fmt

    def run(self) -> None:
        try:
            msg = run_split(self._bv, self._out_dir, self._fmt)
            binaryninja.log_info(msg)
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI log
            binaryninja.log_error(f"delink: split failed: {exc}")


def _cmd_split(bv: BinaryView) -> None:
    out_dir = interaction.get_directory_name_input("delink output directory")
    if not out_dir:
        return
    _SplitTask(bv, out_dir, _pick_format(bv)).start()


def _cmd_export_groups(bv: BinaryView) -> None:
    path = interaction.get_save_filename_input(
        "Export grouping JSON", "*.json", grouping.CONFIG_FILENAME)
    if not path:
        return
    ext = "obj" if _pick_format(bv) == "coff" else "o"
    _model, groups = _build_groups(bv, ext)
    grouping.save(groups, path)
    binaryninja.log_info(f"delink: wrote grouping JSON to {path}")


def _cmd_import_groups(bv: BinaryView) -> None:
    # Accepts any grouping JSON in delink's schema, so a delink idapro.json works too.
    path = interaction.get_open_filename_input("Import grouping JSON", "*.json")
    if not path:
        return
    groups = grouping.load(path)
    components.components_from_groups(bv, groups)
    binaryninja.log_info(f"delink: created components from {path}")


def register() -> None:
    global _registered
    if _registered:
        return
    Settings().register_group(_SETTINGS_GROUP, "Delink")
    Settings().register_setting("delink.outputFormat",
        '{"title":"Output format","type":"string","default":"auto",'
        '"enum":["auto","coff","elf"],"description":"Object file format for delink output."}')
    PluginCommand.register("Delink\\Split to objects...",
                           "Split the analyzed image into object files", _cmd_split)
    PluginCommand.register("Delink\\Export grouping JSON",
                           "Write binja.json from components or default", _cmd_export_groups)
    PluginCommand.register("Delink\\Import grouping JSON",
                           "Create components from a grouping JSON (binja.json / idapro.json)",
                           _cmd_import_groups)
    _registered = True
