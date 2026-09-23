"""model.Function range handling (issue #4)."""

from __future__ import annotations

from binja_delink.model import Function


def test_single_range_is_the_span():
    f = Function(0x1000, 0x1040, "f")
    assert f.ranges == ((0x1000, 0x1040),)
    assert f.size() == 0x40
    assert f.contiguous()
    assert f.entry_offset() == 0


def test_ranges_are_sorted_and_merged():
    f = Function(0x1000, 0, "f", ranges=((0x1080, 0x1100), (0x1000, 0x1010), (0x1010, 0x1020)))
    assert f.ranges == ((0x1000, 0x1020), (0x1080, 0x1100))
    assert f.end == 0x1100


def test_gap_is_not_part_of_the_function():
    f = Function(0x1000, 0, "f", ranges=((0x1000, 0x1010), (0x1080, 0x1100)))
    assert f.size() == 0x10 + 0x80      # emitted bytes
    assert f.span() == 0x100            # gap included
    assert not f.contiguous()
    assert f.contains(0x1008)
    assert not f.contains(0x1040)       # belongs to some other function
    assert f.offset_of(0x1040) is None


def test_offsets_are_relative_to_the_concatenation():
    f = Function(0x1000, 0, "f", ranges=((0x1000, 0x1010), (0x1080, 0x1100)))
    assert f.offset_of(0x1000) == 0
    assert f.offset_of(0x100F) == 0x0F
    assert f.offset_of(0x1080) == 0x10
    assert f.offset_of(0x1084) == 0x14


def test_entry_need_not_be_the_lowest_address():
    f = Function(0x1080, 0, "f", ranges=((0x1000, 0x1010), (0x1080, 0x1100)))
    assert f.start == 0x1080            # the entry point identifies the function
    assert f.entry_offset() == 0x10
