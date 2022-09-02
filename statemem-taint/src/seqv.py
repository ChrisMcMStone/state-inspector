import argparse
import json
import logging
import networkx as nx
import string
import sys
import triton
import malloc_align as ma

from collections import namedtuple
from intervaltree import Interval, IntervalTree
from itertools import chain
from os import path

from loader import ida_loader, Image

logger = logging.getLogger("statemem-static")

Register = namedtuple("Register", ["id", "content"])
MemoryRegion = namedtuple("MemoryRegion", ["virtual_address", "content", "file"])

# this is hacky, but I can't be bothered to do it by hand..
REG_MAP = {
    r.lower(): getattr(triton.REG.X86_64, r)
    for r in dir(triton.REG.X86_64) if not r.startswith("__")
}


class Dependency(object):
    def __init__(self, load, ctx, branch=None, branch_target=None):
        self.load_address = load
        if branch is not None:
            self.depends = branch.isTainted()
            self.branch_address = branch.getAddress()
            self.branch_taken = branch.isConditionTaken()
            self.branch_target = ctx.getConcreteRegisterValue(
                ctx.registers.rip)
        elif branch_target is not None:
            self.depends = True
            self.branch_address = None  # unknown
            self.branch_taken = None  # no idea, but likely
            self.branch_target = branch_target.getAddress()
        else:
            raise ValueError("must specify either branch or branch_target")

    def is_dependent(self):
        return self.depends

    def is_direct_dependent(self):
        return self.depends and self.branch_address is None

    def to_dict(self):
        return {
            "load_address": self.load_address,
            "branch_address": self.branch_address,
            "branch_target": self.branch_target,
            "branch_taken": self.branch_taken,
        }

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "0x{:x}/{} => {:x} {}".format(
            self.load_address,
            hex(self.branch_address) if self.branch_address is not None else
            None, self.branch_target, "T" if self.branch_taken else "F")


def build_cfg(f, rebase=None):
    r = lambda a: a + rebase if rebase is not None else a
    cfg = nx.DiGraph()
    for b in f["blocks"]:
        cfg.add_node(r(b["start_addr"]))
        for d in b["dests"]:
            cfg.add_edge(r(b["start_addr"]), r(d))
    return cfg


def get_state(ctx, heap, segments):
    STACK_SAVE_BYTES = 8192

    # load segments
    segs = []
    for segment in segments:
        new_content = ctx.getConcreteMemoryAreaValue(segment.virtual_address,
                                                     len(segment.content))
        segs.append(MemoryRegion(segment.virtual_address, new_content, None))

    # load stack
    rsp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
    stack_content = ctx.getConcreteMemoryAreaValue(rsp, STACK_SAVE_BYTES)
    new_stack = MemoryRegion(rsp, stack_content, None)

    # load heap
    heap_content = ctx.setConcreteMemoryAreaValue(heap.virtual_address, len(heap.content))
    new_heap = MemoryRegion(heap.virtual_address, heap_content, None)

    # load registers
    registers = []
    for register in REG_MAP:
        reg_id = ctx.getRegister(register)
        reg_val = ctx.getConcreteRegisterValue(reg_id)
        registers.append(Register(reg_id, reg_val))

    return (registers, new_stack, new_heap, segs)


def set_state(ctx, registers, stack, heap, segments):
    # load basic memory
    for segment in segments:
        ctx.setConcreteMemoryAreaValue(segment.virtual_address,
                                       segment.content)

    # load stack
    ctx.setConcreteMemoryAreaValue(stack.virtual_address, stack.content)
    # load heap
    ctx.setConcreteMemoryAreaValue(heap.virtual_address, heap.content)

    for register in registers:
        reg = ctx.getRegister(register.id)
        ctx.setConcreteRegisterValue(reg, register.content)

    return ctx


def analyse_full(ctx, start, ranges, merges, window=200):
    # reset taint on memory + registers
    # TODO: Should we do this? It is possible that the tainted
    # read prior to the branch (i.e., the watchpoint hit data)
    # will later be used following the branch to perform some
    # state-impacting operation. However, we need to overtaint
    # to acheive this
    for m in ctx.getTaintedMemory():
        ctx.untaintMemory(m)
    for r in ctx.getTaintedRegisters():
        ctx.untaintRegister(r)

    pc = ctx.setConcreteRegisterValue(ctx.registers.rip, start)

    while window > 0 and pc not in merges:
        # run via branch until:
        #    1) window depletion
        #    2) hit merge

        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
        opc = ctx.getConcreteMemoryAreaValue(pc, 16)

        insn = triton.Instruction()
        insn.setAddress(pc)
        insn.setOpcode(opc)

        ctx.processing(insn)

        if insn.getType() == triton.OPCODE.X86.HLT:
            return False # found nothing

        for (acc, _) in chain(insn.getStoreAccess(), insn.getLoadAccess()):
            addr = acc.getAddress()
            size = acc.getSize()
            if ranges.overlaps(addr, addr + size):
                return True # OK, accesses assumed state memory
            # taint memory accessed to see if it later used within a merged flow
            ctx.setTaintMemory(acc, True)
        window -= 1

    while window > 0:
        # we only enter this if we're in a merge, otherwise we'd have already returned
        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
        opc = ctx.getConcreteMemoryAreaValue(pc, 16)

        insn = triton.Instruction()
        insn.setAddress(pc)
        insn.setOpcode(opc)

        ctx.processing(insn)

        if insn.getType() == triton.OPCODE.X86.HLT:
            return False # found nothing

        for (acc, _) in chain(insn.getStoreAccess(), insn.getLoadAccess()):
            addr = acc.getAddress()
            size = acc.getSize()
            if ranges.overlaps(addr, addr + size) and insn.isTainted():
                # OK, accesses assumed state memory and the access was performed
                # dependent upon previously tainted memory
                return True
        window -= 1


def analyse_extended(ctx, start, wp, wp_size, ranges, window=200):
    ctx.setConcreteRegisterValue(ctx.registers.rip, start)
    while window > 0:
        window -= 1

        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
        opc = ctx.getConcreteMemoryAreaValue(pc, 16)

        insn = triton.Instruction()
        insn.setAddress(pc)
        insn.setOpcode(opc)

        ctx.processing(insn)

        if insn.getType() == triton.OPCODE.X86.HLT:
            break

        for (acc, _) in insn.getStoreAccess():
            addr = acc.getAddress()
            size = acc.getSize()
            if (addr >= wp and addr < wp+wp_size) or ranges.overlaps(addr, addr + size):
                logger.info("extended analysis: taint influenced branch writes to state mem %#x" % addr)
                return True

    return False


def resolve_block_end(ctx, blk):
    target = blk["end_addr"]
    next_addr = blk["start_addr"]
    insn = triton.Instruction()

    while next_addr != target:
        opc = ctx.getConcreteMemoryAreaValue(next_addr, 16)
        insn.setOpcode(opc)
        insn.setAddress(next_addr)
        ctx.disassembly(insn)
        next_addr += insn.getSize()

    return insn.getAddress()


def resolve_jmp_pred(ctx, binary, wp, wp_size, blk, rebase):
    # NOTE:
    # Handling of stepping back on a block boundary when the dest appears to be a
    # jump target. In the simple case, we have one pred. block for the current
    # block.
    #
    # If we have multiple incoming edges, then we collect all candidates the could
    # have performed memory accesses. We process each instruction and attempt to:
    #
    # 1) reach the target block reported as the pc in the watchpoint hit (i.e., load_pc)
    # 2) the memory reported in the watchpoint hit (i.e., wp)

    cfg = build_cfg(blk.data["function"], rebase)
    preds = list(cfg.predecessors(blk.begin))

    if len(preds) == 1:
        n_blk = next(iter(binary.blocks.at(preds[0])), None)
        if n_blk is not None:
            return resolve_block_end(ctx, n_blk)
    elif len(preds) > 1:
        candidates_clobber = []
        candidates_badaddr = []
        for pred in preds:
            pc = resolve_block_end(ctx, pred)
            opc = ctx.getConcreteMemoryAreaValue(pc, 16)
            insn = triton.Instruction()
            insn.setOpcode(opc)
            insn.setAddress(pc)
            ctx.disassembly(insn)

            operands = insn.getOperands()
            first_clobber = len(operands) > 1

            # now we look at the operands to the insn
            for i, opr in enumerate(operands):
                if opr.getType() != triton.OPERAND.MEM:
                    continue

                # check if a register is clobbered by the load
                clobber = None
                if first_clobber and operands[0].getType() == triton.OPERAND.REG:
                    clobber = operands[0].getId()

                base = opr.getBaseRegister()
                index = opr.getIndexRegister()

                if clobber in (base.getId(), index.getId()):
                    # watchpoint hit depends on clobbered register
                    # cannot determine the actual load access
                    candidates_clobber.append(pc)
                    continue

                disp = opr.getDisplacement()
                scale = opr.getScale()

                bits = disp.getBitSize()
                base = ctx.getConcreteRegisterValue(base) if base.getId() != 0 \
                    else triton.Immediate(0, bits)
                index = ctx.getConcreteRegisterValue(index) if index.getId() != 0 \
                    else triton.Immedddiate(0, bits)

                addr = (base.getValue() + (index.getValue() * scale.getValue()) + scale.getValue()) \
                    % (2**bits-1)

                if addr >= wp and addr < wp+wp_size:
                    return pc

                # NOTE: if we get here, the load didn't resolve to the WP; we need
                # to investigate if this pred. could be viable still and under what
                # circumstances.

            # In absence of a perfect match, we prefer clobbers, and then bad matches
            return next(chain(candidates_clobber, candidates_badaddr))

    return None


def analyse(ctx, binary, wp, wp_size, load_pc, window, state, rebase=None, extended=False):
    logger.info("analysing watchpoint hit at %#x" % load_pc)

    blk = next(iter(binary.blocks.at(load_pc)))

    pc = blk.begin

    if load_pc == blk.begin:
        # case of jump to
        n_pc = resolve_jmp_pred(ctx, binary, wp, wp_size, blk, rebase)
        if n_pc is not None:
            pc = n_pc
        else:
            logger.warn(
                "watchpoint hit appears to be a jump target; cannot determine origin pc"
            )

            opc = ctx.getConcreteMemoryAreaValue(pc, 16)
            insn = triton.Instruction()
            insn.setOpcode(opc)
            insn.setAddress(pc)
            ctx.disassembly(insn)
            return Dependency(wp, ctx, branch_target=insn)

    logger.info("stepped back to block start at %#x" % pc)
    opc = ctx.getConcreteMemoryAreaValue(pc, 16)
    insn = triton.Instruction()
    insn.setOpcode(opc)
    insn.setAddress(pc)
    ctx.disassembly(insn)

    while insn.getNextAddress() != load_pc:
        pc = insn.getNextAddress()
        opc = ctx.getConcreteMemoryAreaValue(pc, 16)
        insn = triton.Instruction()
        insn.setOpcode(opc)
        insn.setAddress(pc)
        ctx.disassembly(insn)
        logger.info("stepping... %#x" % pc)

    # NOTE:
    # reset the memory; this is a hack since Triton won't give us the loads/stores
    # until we process the instruction, which causes memory + registers to be updated
    # unfortunately, we only have a capture of the state from ptrace after this
    # instruction has been executed. If there are side-effects on the memory, then we
    # need to roll them back... since this uses the state after that instruction, there
    # might be other issues due to side-effects, especially if the instruction itself
    # is a conditional (e.g., cmov)
    ctx.processing(insn)
    set_state(ctx, *state)

    hit_pc = pc
    pc = load_pc

    logger.info("setting up taint on load accesses")

    # introduce taint;
    for (load, _) in insn.getLoadAccess():
        ctx.setTaintMemory(load, True)
    for (store, _) in insn.getStoreAccess():
        ctx.setTaintMemory(store, True)
    for (reg, _) in insn.getWrittenRegisters():
        ctx.setTaintRegister(reg, True)

    call_depth = 0

    logger.info("propagating taint to next local branch")
    while pc and window > 0:
        opc = ctx.getConcreteMemoryAreaValue(pc, 16)

        insn = triton.Instruction()
        insn.setOpcode(opc)
        insn.setAddress(pc)

        ctx.processing(insn)
        logger.info("taint to %s " % hex(insn.getAddress()))

        # HEURISTIC: real logic decisions are made in higher level functions
        # e.g., do not report the comparison inside a strcmp(., .), but do report
        # the control-flow dependent on its return value
        #
        # e.g., does the return value depend on the hit value and then influence
        # a decision in the caller of this function
        if insn.isBranch() and call_depth <= 0:
            logger.info("reached intraprocedural control-flow; "
                        "recording dependency information")
            return Dependency(hit_pc, ctx, branch=insn)
        # TODO: this will now allow us to follow interprocedural control-flow;
        # it remains a question if we should then make a stack to decide if we
        # should treat the next branch as something we want to terminate the
        # above check on. NOTE: needs testing.
        elif (not extended and insn.isControlFlow()) or insn.getType() == triton.OPCODE.X86.HLT:
            # here we would diverge into non-localised control flow
            logger.warn(
                "reached interprocedural control-flow; aborted analysis")
            return None
        elif insn.getType() == triton.OPCODE.X86.CALL:
            call_depth += 1
        elif insn.getType() in (triton.OPCODE.X86.RET, triton.OPCODE.X86.IRET):
            call_depth -= 1

        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
        window -= 1

    logger.warn("expended execution window in attempting to find "
                "intraprocedural control-flow; aborted analysis")
    return None


def load_binary(ida_path, bin_path):
    logger.info("loading binary from %s using IDA Pro at %s" %
                (bin_path, ida_path))
    return ida_loader(ida_path, bin_path)


def init_context(binary, state):
    ctx = triton.TritonContext()
    if binary.arch == "metapc":
        if binary.bits == 32:
            ctx.setArchitecture(triton.ARCH.X86)
        else:  # binary.bits == 64
            ctx.setArchitecture(triton.ARCH.X86_64)
    else:
        logger.critical('unsupported architecture')
        sys.exit(-1)

    ctx.setMode(triton.MODE.ALIGNED_MEMORY, True)
    ctx.setMode(triton.MODE.TAINT_THROUGH_POINTERS, True)
    ctx.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

    logger.info('initialising new context')
    return set_state(ctx, *state)


def read_binary(base, path, name):
    with open(path, "rb") as f:
        return MemoryRegion(base, bytes(f.read()), name)


def read_registers(path):
    with open(path, "r") as f:
        return [Register(REG_MAP[r["name"]], r["value"]) for r in json.load(f)]


def read_meta(prefix):
    with open(prefix + ".log", "r") as log:
        jsn = json.load(log)
        watchpoint = jsn["address"]
        orig_watchpoint = jsn["orig_address"]
        wp_size = jsn["size"]
        pc = jsn["pc"]
        stack_base = jsn["stack_base"]
        heap_base = jsn["heap_base"]
        malloc_log = jsn["malloc_log"]
        registers = [
            Register(REG_MAP[k], v) for k, v in jsn["registers"].items()
            if k in REG_MAP
        ]
        segments = [read_binary(s["low"], s["dump"], s["name"]) for s in jsn["segments"]]
        return (malloc_log, watchpoint, orig_watchpoint, wp_size, pc, stack_base, heap_base, registers, segments)


def cfg_merges(cfg, p1, p2):
    return nx.algorithms.dag.descendants(cfg, p1).intersection(
        nx.algorithms.dag.descendants(cfg, p2))

def find_binary(segment, binaries):
    name = path.basename(segment.file)
    return next(b for n, b in binaries.items() if path.basename(n) == name)

def main():
    global debug
    cli = argparse.ArgumentParser()
    cli.add_argument("--binaries", help="binaries to analyse",
                     required=True,
                     nargs='+')
    cli.add_argument("--ida", help="absolute path to IDA Pro", required=True)
    cli.add_argument("--watchpoints",
                     help="list of watchpoint prefixes to analyse",
                     required=True,
                     nargs='+')
    cli.add_argument("--window",
                     help="basic block instruction execution bound",
                     default=64,
                     type=int)
    cli.add_argument("--debug",
                     help="print debug information",
                     default=False,
                     action="store_true")
    cli.add_argument("--extended",
                     help="perform extended analysis using ranges in file",
                     default=None,
                     type=str)
    cli.add_argument("--repr-mallocs",
                     help="representative malloc log to align watchpoint mallocs against",
                     default=None,
                     type=str)

    args = cli.parse_args()
    logging.basicConfig(format="%(asctime)s (%(levelname)s): %(message)s",
                        level=logging.DEBUG if args.debug else logging.CRITICAL)

    binaries = {name: load_binary(args.ida, name) for name in args.binaries}
    # binary = load_binary(args.ida, args.binary)
    logger.info("binaries successfully loaded")

    json_output = []

    for prefix in args.watchpoints:
        mallocs, wp, o_wp, wp_size, pc, sb, hb, registers, segments = read_meta(prefix)

        ext_ranges = None
        if args.extended is not None:
            with open(args.extended, "r") as xf:
                logger.info("loading suspected state memory ranges from %s" %
                            args.extended)
                # NOTE: format is an iterable providing __getitem__ of len > 2 with index 0
                #       as address and index 1 as size (in bytes)
                this_mallocs = ma.build_mallocs(mallocs)[0]
                repr_mallocs = ma.build_mallocs(args.repr_mallocs)[0]

                # realign the mallocs so the repr. memory corresponds
                # to the dumps

                if len(this_mallocs) <= len(repr_mallocs):
                    mapping = ma.build_mapping(this_mallocs, repr_mallocs)
                    kv_sel = lambda v: (v[1], v[0])
                else:
                    mapping = ma.build_mapping(repr_mallocs, this_mallocs)
                    kv_sel = lambda v: (v[0], v[1])

                iv_map = IntervalTree(
                    Interval(k[0].ret, k[0].ret+k[0].size, v[0]) for (k, v) in map(kv_sel, mapping)
                )

                def translate(addr, size):
                    iv = iv_map.overlap(addr, addr+size).pop()
                    begin = addr-iv.begin+iv.data.ret
                    return Interval(begin, begin+size)

                ext_ranges = IntervalTree(
                    translate(int(v[0], 0), int(v[1], 0))
                    for v in map(lambda l: l.split(" "), xf.readlines()))

        rebase = None
        local_pc = False
        binary = None
        for i in range(len(segments)):
            if pc >= segments[i].virtual_address and pc < segments[
                    i].virtual_address + len(segments[i].content):
                # rebase...
                binary = find_binary(segments[i], binaries)
                iv = binary.blocks.at(pc)
                rebase = segments[i].virtual_address if len(iv) == 0 else None
                if rebase is not None:
                    binary.rebase(rebase)

                local_pc = True

                if args.extended is None:
                    iv = next(iter(binary.blocks.at(pc)))
                    # merge contiguous blocks, since IDA blocks aren't true basic blocks
                    # should we also do this for direct jumps?
                    while len(iv.data["dests"]
                              ) == 1 and iv.data["dests"][0] == iv.end:
                        iv_fall = next(iter(binary.blocks.at(iv.end)))
                        iv = Interval(iv.begin, iv_fall.end, iv_fall.data)

                    # optimisation: load only what state we need to perform analysis
                    offset = iv.begin - segments[i].virtual_address
                    segments[i] = MemoryRegion(
                        iv.begin,
                        segments[i].content[offset:offset +
                                            min(iv.end -
                                                iv.begin, args.window * 16)])
                break
        if not local_pc:
            logger.warn("watchpoint is not contained within program owned "
                        "segment; likely in shared library code; skipping "
                        "analysis")
            continue

        stack = read_binary(sb, prefix + "_stack.dump", "stack")
        heap = read_binary(hb, prefix + "_heap.dump", "heap")

        state = (registers, stack, heap, segments)

        ctx = init_context(binary, state)
        info = analyse(ctx, binary, wp, wp_size, pc, args.window, state, extended=args.extended)

        # NOTE: detecting direct dep. is no longer useful since we can't track anything
        # TODO: clean up and remove such branches
        if info is not None and info.is_dependent() and not info.is_direct_dependent():
            blk = next(iter(binary.blocks.at(info.branch_address)))
            cfg = build_cfg(blk.data["function"], rebase)
            start = blk.data["function"]["address"]
            start = start + rebase if rebase is not None else start
            idoms = nx.algorithms.dominance.immediate_dominators(cfg, start)
            tgt_dom = idoms[info.branch_target]

            # TODO(slt): handle the case where we merged multiple IDA basic
            # blocks here, we'd use the last block merged, rather than the
            # first to compute the dominance check

            rblk = blk
            while len(rblk.data["dests"]) == 1 and rblk.data["dests"][0] == rblk.end:
                iv_fall = next(iter(binary.blocks.at(rblk.end)))
                rblk = Interval(rblk.begin, iv_fall.end, iv_fall.data)

            while blk.begin != tgt_dom and len(
                    blk.data["dests"]
            ) == 1 and blk.data["dests"][0] == blk.end:
                iv_fall = next(iter(binary.blocks.at(blk.end)))
                blk = Interval(blk.begin, iv_fall.end, iv_fall.data)

            # TODO(slt): document the output

            save_state = get_state(ctx, heap, segments)

            ext = None
            if args.extended:
                ext = False
                for dest in blk.data["dests"]:
                    start = dest.begin
                    set_state(ctx, *save_state)
                    if analyse_extended(ctx, start, wp, wp_size, ext_ranges):
                        ext = True
                        break
            if ext is None: ext = False

            if len(blk.data["dests"]) == 2 and args.extended is not None:
                merges = cfg_merges(cfg, *blk.data["dests"])
                full = None
                for dest in blk.data["dests"]:
                    start = dest.begin
                    set_state(ctx, *save_state)
                    if analyse_full(ctx, start, ext_ranges, merges):
                        full = True
                        break
                if full is None: full = False
                json_output.append( {
                    "pc":pc,
                    "watchpoint": wp,
                    "orig_watchpoint": o_wp,
                    "dependency": info.to_dict(),
                    "single_incoming": tgt_dom == blk.begin,
                    "extended_check": ext,
                    "full_check": full,
                } )
            else:
                json_output.append( {
                    "pc":pc,
                    "watchpoint": wp,
                    "orig_watchpoint": o_wp,
                    "dependency": info.to_dict(),
                    "single_incoming": tgt_dom == blk.begin,
                    "extended_check": ext,
                    "full_check": False,
                } )

            # merges = cfg_merges(cfg, ...)
            # full = analyse_full(ctx, ext_ranges, merges)
    json.dump(json_output, sys.stdout)

if __name__ == "__main__":
    main()
