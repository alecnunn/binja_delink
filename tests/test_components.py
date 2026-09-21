"""Component-driven grouping (Binja-free half of components.py)."""

from __future__ import annotations

from binja_delink.components import groups_from_component_map
from binja_delink.model import Arch, Function, Model, Section, SegClass

TEXT = Section("text", 0x1000, 0x2000, True, False, True, SegClass.CODE)


def make_model(functions):
    return Model(arch=Arch.X86_64, bits=64, little_endian=True, image_base=0x1000,
                 filetype="PE", input_file="sample.exe", sections=[TEXT],
                 functions=list(functions), symbols=[], relocations=[])


def test_components_become_objects_and_loose_functions_stand_alone():
    model = make_model([Function(0x1000, 0x1010, "a"), Function(0x1010, 0x1020, "b"),
                        Function(0x1020, 0x1030, "loose")])
    groups = groups_from_component_map({"core": [0x1000, 0x1010]}, model, "o")
    assert sorted(groups) == ["core.o", "loose.o"]
    assert sorted(groups["core.o"]) == ["a", "b"]


def test_a_function_lands_in_the_first_component_that_claims_it():
    model = make_model([Function(0x1000, 0x1010, "a")])
    groups = groups_from_component_map({"first": [0x1000], "second": [0x1000]}, model, "o")
    assert list(groups) == ["first.o"]


def test_non_contiguous_function_records_the_bytes_it_emits():
    func = Function(0x1000, 0, "split_fn", ranges=((0x1000, 0x1010), (0x1080, 0x10A0)))
    groups = groups_from_component_map({"core": [0x1000]}, make_model([func]), "o")
    assert groups["core.o"]["split_fn"].size == 0x30      # the gap is not ours to emit
