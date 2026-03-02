# -*- coding: utf-8 -*-
"""Binary Ninja exporter."""
import sys
import os
# sys.path manipulation
current_dir = os.path.dirname(os.path.realpath(__file__))
plugin_dir = os.path.abspath(os.path.join(current_dir, "..",".."))
sys.path.insert(1,plugin_dir)
from collections.abc import Iterator

import recover
from recover.exporter import Exporter, Segment, SegmentClass
from recover.graphs import PDG, EdgeType, EdgeClass, NodeType

import itertools
import logging

import networkx
try:
    import binaryninja as bn
    from binaryninja import (
        BinaryView,
        Function,
        BasicBlock,
        SectionSemantics,
        SegmentFlag,
        ReferenceType,
    )
except ImportError:
    print("Unable to import binaryninja API - Exiting")
    sys.exit(-1)


__author__ = "Chariton Karamitas <huku@census-labs.com>"
__credits__ = ["Chariton Karamitas <huku@census-labs.com>", "Athanasios Kostopoulos <athanasios@akostopoulos.com>"]
__maintainer__ = "Athanasios Kostopoulos <athanasios@akostopoulos.com>"

__all__ = ["BinjaExporter"]


AGGRESSIVE = False

# Binary Ninja instance — set this before using the exporter,
# or pass a BinaryView to IdaPro/BinjaExporter directly.
_bv: BinaryView = None


def _set_bv(bv: BinaryView) -> None:
    global _bv
    _bv = bv


# ---------------------------------------------------------------------------
# Helpers that mirror the IDA utility functions
# ---------------------------------------------------------------------------

def _is_badaddr(ea: int) -> bool:
    return ea is None or ea == bn.core.BADADDR or ea >= 0xFF00000000000000


def _is_named(ea: int) -> bool:
    sym = _bv.get_symbol_at(ea)
    return sym is not None


def _is_labeled(ea: int) -> bool:
    """True if the address has a user/auto label or is referenced by name."""
    sym = _bv.get_symbol_at(ea)
    if sym is not None:
        return True
    # Also treat it as labeled if it has incoming code/data references
    return bool(_bv.get_code_refs(ea) or _bv.get_data_refs(ea))


def _is_referenced(ea: int) -> bool:
    return bool(_bv.get_code_refs(ea) or _bv.get_data_refs(ea))


def _is_data(ea: int) -> bool:
    """True when the address is data or undefined (not code)."""
    return not _is_code(ea)


def _is_code(ea: int) -> bool:
    funcs = _bv.get_functions_containing(ea)
    return bool(funcs)


def _get_ea_info(ea: int) -> tuple[int, int]:
    var = _bv.get_data_var_at(ea)
    if var is not None:
        size = var.type.width if var.type else 1
    else:
        size = _bv.get_instruction_length(ea) or 1
    return ea, size


# ---------------------------------------------------------------------------
# PDG builder
# ---------------------------------------------------------------------------

class _PdgBuilder:
    """Builds PDG using Binary Ninja APIs."""

    def __init__(self, bv: BinaryView) -> None:
        self._bv = bv
        self._logger = logging.getLogger(self.__class__.__name__)
        self._pdg = PDG()

    # ------------------------------------------------------------------
    # Node / edge helpers
    # ------------------------------------------------------------------

    def _segment_index(self, ea: int) -> int:
        seg = self._bv.get_segment_at(ea)
        # Use the segment start as a stable numeric identifier
        return seg.start if seg else 0

    def _node_name(self, ea: int, node_type: NodeType) -> str:
        sym = self._bv.get_symbol_at(ea)
        if sym:
            return sym.name
        return f"{node_type.name}:{ea:#x}"

    def _add_program_node(
        self, node: int, node_type: NodeType = NodeType.INVALID
    ) -> None:

        if node_type == NodeType.INVALID:
            if _is_code(node):
                node_type = NodeType.CODE
            else:
                node_type = NodeType.DATA

        segment = self._segment_index(node)
        name = self._node_name(node, node_type)

        self._pdg.add_program_node(
            node, node_type=node_type, segment=segment, name=name
        )
        self._logger.debug("%s/%#x (%s)", name, node, node_type.name)

    def _add_program_edge(
        self,
        tail: int,
        head: int,
        edge_type: EdgeType = EdgeType.INVALID,
        edge_class: EdgeClass = EdgeClass.INVALID,
        size: int = 0,
    ) -> None:

        if edge_type == EdgeType.INVALID:
            if _is_code(tail):
                edge_type = EdgeType.CODE2CODE if _is_code(head) else EdgeType.CODE2DATA
            else:
                edge_type = EdgeType.DATA2CODE if _is_code(head) else EdgeType.DATA2DATA

        for data in self._pdg.get_edge_data(tail, head, default={}).values():
            if data["edge_class"] == edge_class:
                break
        else:
            self._pdg.add_program_edge(
                tail, head, edge_type=edge_type, edge_class=edge_class, size=size
            )

        self._logger.debug("%#x -> %#x (%s)", tail, head, edge_type.name)

    # ------------------------------------------------------------------
    # Head / dref processing
    # ------------------------------------------------------------------

    def _process_heads(self, ea: int) -> Iterator[tuple[int, int]]:
        if _is_labeled(ea):
            yield _get_ea_info(ea)

            if AGGRESSIVE:
                # Walk forward through data items until we hit something labeled
                # or non-data (mirrors IDA's next_head loop)
                cur = ea + (_get_ea_info(ea)[1] or 1)
                while cur < self._bv.end:
                    if _is_labeled(cur) or not _is_data(cur):
                        break
                    # Skip alignment (BN has no direct is_align; approximate
                    # by checking if the address is a nop-like padding)
                    yield _get_ea_info(cur)
                    step = _get_ea_info(cur)[1] or 1
                    cur += step

    def _process_drefs(
        self, ea: int, seen: set[int] | None = None
    ) -> Iterator[tuple[int, int]]:

        if not seen:
            seen = set()

        # Resolve to function start if inside a function
        funcs = self._bv.get_functions_containing(ea)
        src_ea = funcs[0].start if funcs else ea

        for ref_ea in self._bv.get_data_refs_from(ea):
            if _is_data(ref_ea):
                for head_ea, head_size in self._process_heads(ref_ea):
                    if head_ea not in self._pdg:
                        self._add_program_node(head_ea)
                    self._add_program_edge(
                        src_ea,
                        head_ea,
                        edge_class=EdgeClass.DATA_RELATION,
                        size=head_size,
                    )
                    yield head_ea, head_size

                    if head_ea not in seen:
                        seen.add(head_ea)
                        yield from self._process_drefs(head_ea, seen=seen)

            elif _is_code(ref_ea):
                head_ea, head_size = _get_ea_info(ref_ea)
                ref_funcs = self._bv.get_functions_containing(head_ea)
                if ref_funcs:
                    head_ea = ref_funcs[0].start
                if head_ea not in self._pdg:
                    self._add_program_node(head_ea)
                self._add_program_edge(
                    src_ea, head_ea, edge_class=EdgeClass.DATA_RELATION, size=head_size
                )
                yield head_ea, head_size

    # ------------------------------------------------------------------
    # Function processing
    # ------------------------------------------------------------------

    def _process_func(self, func: Function) -> Iterator[tuple[int, int]]:

        for bb in func.basic_blocks:
            if bb.start == bb.end:
                continue
            if not _is_code(bb.start):
                continue

            # Iterate instructions in the basic block
            ea = bb.start
            while ea < bb.end:
                self._logger.debug("Processing %#x", ea)
                yield from self._process_drefs(ea)
                length = self._bv.get_instruction_length(ea)
                ea += length if length else 1

    def _add_data_to_code_edges_func(self, func: Function) -> None:
        for succ_ea, succ_size in self._process_func(func):
            if _is_code(succ_ea):
                succ_funcs = self._bv.get_functions_containing(succ_ea)
                if succ_funcs:
                    self._add_program_edge(
                        func.start,
                        succ_funcs[0].start,
                        edge_class=EdgeClass.CONTROL_RELATION,
                        edge_type=EdgeType.CODE2CODE,
                        size=succ_size,
                    )

    def _add_data_to_code_edges(self) -> None:
        num_edges = self._pdg.number_of_edges()
        for func in self._bv.functions:
            self._add_data_to_code_edges_func(func)
        self._logger.info(
            "Added %d data-to-code reference edges",
            self._pdg.number_of_edges() - num_edges,
        )

    def _add_sequence_edges(self) -> None:
        funcs = sorted(self._bv.functions, key=lambda f: f.start)
        prev_ea = None
        prev_seg_start = None

        for func in funcs:
            ea = func.start
            seg = self._bv.get_segment_at(ea)
            seg_start = seg.start if seg else None
            if prev_ea is not None and prev_seg_start == seg_start:
                self._add_program_edge(
                    prev_ea,
                    ea,
                    edge_class=EdgeClass.SEQUENCE,
                    edge_type=EdgeType.CODE2CODE,
                )
            prev_ea = ea
            prev_seg_start = seg_start

    def _add_density_edges(self, depth_limit: int = 1, window: int = 1) -> None:

        def _splice(node_idx: list[int], window: int) -> Iterator[list[int]]:
            while node_idx:
                i = node_idx.pop(0)
                seq = [i]
                while node_idx and abs(node_idx[0] - i) <= window:
                    i = node_idx.pop(0)
                    seq.append(i)
                yield seq

        nodes = list(sorted(self._pdg))
        density_seqs = []
        for ea in self._pdg:
            successors = [
                nodes.index(node_ea)
                for node_ea in networkx.dfs_preorder_nodes(
                    self._pdg, source=ea, depth_limit=depth_limit, sort_neighbors=sorted
                )
                if node_ea != ea
            ]
            density_seqs += list(_splice(successors, window))

        num_edges = self._pdg.number_of_edges()

        for seq in density_seqs:
            for i, j in itertools.pairwise(seq):
                self._add_program_edge(
                    nodes[i],
                    nodes[j],
                    edge_class=EdgeClass.DENSITY,
                    edge_type=EdgeType.CODE2CODE,
                )
                self._add_program_edge(
                    nodes[j],
                    nodes[i],
                    edge_class=EdgeClass.DENSITY,
                    edge_type=EdgeType.CODE2CODE,
                )

        self._logger.info(
            "Added %d density edges", self._pdg.number_of_edges() - num_edges
        )

    def _get_func_callers(self, ea: int) -> Iterator[Function]:
        """Yield all functions that contain a call to *ea*."""
        for ref in self._bv.get_code_refs(ea):
            caller_funcs = self._bv.get_functions_containing(ref.address)
            for f in caller_funcs:
                yield f

    def _add_fcg_edges(self) -> None:
        for func in self._bv.functions:
            ea = func.start
            if ea not in self._pdg:
                self._add_program_node(ea, node_type=NodeType.CODE)

            for caller in self._get_func_callers(ea):
                pred_ea = caller.start
                if pred_ea not in self._pdg:
                    self._add_program_node(pred_ea, node_type=NodeType.CODE)
                self._add_program_edge(
                    pred_ea,
                    ea,
                    edge_class=EdgeClass.CONTROL_RELATION,
                    edge_type=EdgeType.CODE2CODE,
                )

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def build(self) -> PDG:
        self._logger.info("Adding FCG edges")
        self._add_fcg_edges()
        self._logger.info("Adding sequence edges")
        self._add_sequence_edges()
        self._logger.info("Adding data edges")
        self._add_data_to_code_edges()
        return self._pdg


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------

class BinjaExporter(Exporter):
    """Binary Ninja exporter — drop-in replacement for IdaPro."""

    def __init__(self, bv: BinaryView) -> None:
        super().__init__()
        self._bv = bv
        _set_bv(bv)  # also update module-level helper

    def export_segments(self) -> list[Segment]:
        segs = []

        for seg in self._bv.segments:
            # Try to classify via BN section semantics first
            sclass = SegmentClass.INVALID

            sections = self._bv.get_sections_at(seg.start)
            if sections:
                sem = sections[0].semantics
                if sem == SectionSemantics.ReadOnlyCodeSectionSemantics:
                    sclass = SegmentClass.CODE
                elif sem in (
                    SectionSemantics.ReadWriteDataSectionSemantics,
                    SectionSemantics.ReadOnlyDataSectionSemantics,
                ):
                    sclass = SegmentClass.DATA
                elif sem == SectionSemantics.ExternalSectionSemantics:
                    sclass = SegmentClass.DATA
            else:
                # Fall back to segment flags (mirrors IDA perm logic)
                executable = bool(seg.flags & SegmentFlag.SegmentExecutable)
                writable   = bool(seg.flags & SegmentFlag.SegmentWritable)

                if executable and writable:
                    sclass = SegmentClass.CODE | SegmentClass.DATA
                elif executable:
                    sclass = SegmentClass.CODE
                elif writable or bool(seg.flags & SegmentFlag.SegmentReadable):
                    sclass = SegmentClass.DATA

            # Derive a human-readable name from associated sections
            name = ", ".join(s.name for s in self._bv.get_sections_at(seg.start)) or f"seg_{seg.start:#x}"

            # perm: reconstruct an IDA-style permission byte for compatibility
            perm = 0
            if seg.flags & SegmentFlag.SegmentReadable:
                perm |= 0x4  # SEGPERM_READ
            if seg.flags & SegmentFlag.SegmentWritable:
                perm |= 0x2  # SEGPERM_WRITE
            if seg.flags & SegmentFlag.SegmentExecutable:
                perm |= 0x1  # SEGPERM_EXEC

            segs.append(
                Segment(
                    name,
                    seg.start,
                    seg.end,
                    seg.start,  # sel: use start as stable selector
                    perm,
                    sclass,
                )
            )

        return segs

    def export_pdg(self) -> PDG:
        return _PdgBuilder(self._bv).build()

if __name__ == "__main__":
    print("binja exporter")
    # bv is automatically added by Binja
    print(sys.path)
    print(sys.prefix)
    print(sys.base_prefix)
    exporter = BinjaExporter(bv)
    recover.export(exporter, "/tmp")
