import argparse
import json
import logging
import lief
import networkx as nx
import string
import sys
import triton
import malloc_align as ma

from collections import namedtuple
from intervaltree import Interval, IntervalTree
from itertools import chain
from os import path

from datatracker import DataTrackerLoader
from loader import ida_loader, Image
from lazyloader import ZzzLoader, DumpLoader, LoadableSection
import stubs
import base64

logger = logging.getLogger("depanyl")

Register = namedtuple("Register", ["id", "content"])
MemoryRegion = namedtuple("MemoryRegion", ["virtual_address", "content", "file", "perms"])
ClobberQuery = namedtuple("ClobberQuery", ["ctx", "var", "ast", "query"])


# this is hacky, but I can't be bothered to do it by hand..
REG_MAP = {
    r.lower(): getattr(triton.REG.X86_64, r)
    for r in dir(triton.REG.X86_64) if not r.startswith("__")
}

UNCOND_JMPS = (triton.OPCODE.X86.LJMP, triton.OPCODE.X86.JMP)

# support 32 and 64 bits
IP = None
SP = None
RET = None
WORD_SIZE = None

BASE_RELOCS = 0xDEAD000000000000

STUBBED = [
    (("_printf", "printf"), stubs.debug("printf", logger)),
    (("_shutdown", "shutdown"), stubs.debug("shutdown", logger)),
    (("_close", "close"), stubs.debug("close", logger)),
    (("_exit", "exit"), stubs.exit),
    (("send", "_send"), stubs.send),
    (("_strncmp", "strncmp", "_strcmp", "strcmp"), stubs.strncmp),
    (("_read", "read"), stubs.needs_input("read", logger)),
]

# for a given program
CUSTOM_STUBS = [
    ("default_malloc_ex", stubs.debug("malloc_problem", logger)),
]

DEFAULT_STUB_BASE_ID = len(STUBBED)
DEFAULT_STUB_MAP = None

LIEF_LAST = None

EXP_VALUE = None
LOAD_B4_STORE = None

def plt_mapping(elf):
    PLT_ENTRY_SIZE = 0x10

    plt = next((s for s in elf.sections if s.name == ".plt"), None)
    if plt is None:
        return ((r, None) for r in elf.pltgot_relocations)

    plt_base = plt.virtual_address + PLT_ENTRY_SIZE

    return ((r, plt_base+i*PLT_ENTRY_SIZE)
            for i, r in enumerate(elf.pltgot_relocations))


def init_stubs(loader, binary):
    global LIEF_LAST
    global DEFAULT_STUB_MAP
    binary_name = binary[0]
    DEFAULT_STUB_MAP = dict()
    default_id = DEFAULT_STUB_BASE_ID

    if LIEF_LAST is not None and LIEF_LAST[0] == binary_name:
        elf = LIEF_LAST[1]
    else:
        elf = lief.parse(binary_name)
        LIEF_LAST = (binary_name, elf)

    def rebase(addr):
        return addr-binary[1].imagebase-binary[1].orig_segment_base+binary[1].segment_base

    for reloc, plt_ent in plt_mapping(elf):
        if not reloc.has_symbol:
            continue
        name = reloc.symbol.name
        addr = reloc.address
        reloc_fn = None
        for i, tostub in enumerate(STUBBED):
            if name in tostub[0]:
                loader.ctx.setConcreteMemoryValue(triton.MemoryAccess(rebase(addr), WORD_SIZE), BASE_RELOCS+WORD_SIZE*i)
                reloc_fn = tostub[1]
                break
        if reloc_fn is None:
            # apply default stub function; log and do nothing
            loc = BASE_RELOCS+WORD_SIZE*default_id
            loader.ctx.setConcreteMemoryValue(triton.MemoryAccess(rebase(addr), WORD_SIZE), loc)
            reloc_fn = stubs.debug(name, logger)
            DEFAULT_STUB_MAP[loc] = reloc_fn
            default_id += 1 # each reloc. entry has a unique mapping
        if plt_ent is not None:
            # address in plt
            DEFAULT_STUB_MAP[rebase(plt_ent)] = reloc_fn

    for name, fn in CUSTOM_STUBS:
        f = binary[1].functions.get(name, None)
        if f is not None:
            addr = f["address"]
            DEFAULT_STUB_MAP[addr] = fn



def handle_stubbed(loader, pc):
    # handle .plt stubs
    if DEFAULT_STUB_MAP is not None and pc in DEFAULT_STUB_MAP:
        fn = DEFAULT_STUB_MAP[pc]
        ret_value = fn(loader.ctx)
        if ret_value is not None:
            loader.ctx.setConcreteRegisterValue(RET, ret_value)

        ret_addr = loader.ctx.getConcreteMemoryValue(triton.MemoryAccess(loader.ctx.getConcreteRegisterValue(SP), WORD_SIZE))

        loader.ctx.setConcreteRegisterValue(IP, ret_addr)
        loader.ctx.setConcreteRegisterValue(SP, loader.ctx.getConcreteRegisterValue(SP)+WORD_SIZE)
        return True

    # handle other stubs; likely we don't need this
    for i, rel in enumerate(STUBBED):
        if pc == (BASE_RELOCS+WORD_SIZE*i):
            ret_value = rel[1](loader.ctx)
            if ret_value is not None:
                loader.ctx.setConcreteRegisterValue(RET, ret_value)

            ret_addr = loader.ctx.getConcreteMemoryValue(triton.MemoryAccess(loader.ctx.getConcreteRegisterValue(SP), WORD_SIZE))

            loader.ctx.setConcreteRegisterValue(IP, ret_addr)
            loader.ctx.setConcreteRegisterValue(SP, loader.ctx.getConcreteRegisterValue(SP)+WORD_SIZE)
            return True

    return False


def build_cfg(f):
    """
    Constructs a CFG from information dumped by the loader.
    """
    cfg = nx.DiGraph()
    for b in f["blocks"]:
        cfg.add_node(b["start_addr"])
        for d in b["dests"]:
            cfg.add_edge(b["start_addr"], d)
    return cfg


def get_state(ctx, heap, segments):
    """
    Take a snapshot of the current program state to be used with set_state
    """
    STACK_SAVE_BYTES = 8192

    # load segments
    segs = []
    for segment in segments:
        new_content = ctx.getConcreteMemoryAreaValue(segment.virtual_address,
                                                     len(segment.content))
        segs.append(MemoryRegion(segment.virtual_address, new_content, None, None))

    # load stack
    sp = ctx.getConcreteRegisterValue(SP)
    stack_content = ctx.getConcreteMemoryAreaValue(sp, STACK_SAVE_BYTES)
    new_stack = MemoryRegion(sp, stack_content, None, None)

    # load heap
    heap_content = ctx.getConcreteMemoryAreaValue(heap.virtual_address, len(heap.content))
    new_heap = MemoryRegion(heap.virtual_address, heap_content, None, None)

    # load registers
    registers = []
    for register in REG_MAP:
        reg_id = ctx.getRegister(register)
        reg_val = ctx.getConcreteRegisterValue(reg_id)
        registers.append(Register(reg_id, reg_val))

    return (registers, new_stack, new_heap, segs)


def set_state(loader, binary, registers):
    """
    Sets the engine context using given register, stack, heap
    and segment values.
    """
    loader.reset_backing()

    init_stubs(loader, binary)

    for register in registers:
        reg = loader.ctx.getRegister(register.id)
        loader.ctx.setConcreteRegisterValue(reg, register.content)

    # synch. engines
    loader.ctx.concretizeAllMemory()
    loader.ctx.concretizeAllRegister()


def resolve_block_end(loader, blk):
    """
    Given a block, find the address of the last instruction.
    """
    target = blk.end
    next_addr = blk.begin
    insn = triton.Instruction()

    while next_addr != target:
        opc = loader.ctx.getConcreteMemoryAreaValue(next_addr, 16)
        insn.setOpcode(opc)
        insn.setAddress(next_addr)
        loader.ctx.disassembly(insn)
        next_addr += insn.getSize()

    return insn.getAddress()


def resolve_jmp_pred(loader, binary, wp, wp_size, blk):
    """
    Resolve the last instruction before the current one under the assumption
    that the last instruction was in a different block that has an incoming edge
    to the block containing the current address.
    """
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

    cfg = build_cfg(blk.data["function"])
    preds = list(cfg.predecessors(blk.begin))

    if len(preds) == 1:
        n_blk = next(iter(binary.blocks.at(preds[0])), None)
        if n_blk is not None:
            return resolve_block_end(loader.ctx, n_blk)
    elif len(preds) > 1:
        candidates_clobber = []
        candidates_badaddr = []
        for pred in preds:
            pred_block = next(iter(binary.blocks.at(pred)), None)
            pc = resolve_block_end(loader, pred_block)
            opc = loader.ctx.getConcreteMemoryAreaValue(pc, 16)
            insn = triton.Instruction()
            insn.setOpcode(opc)
            insn.setAddress(pc)
            loader.ctx.disassembly(insn)

            operands = insn.getOperands()
            first_clobber = len(operands) > 1

            # now we look at the operands to the insn
            for i, opr in enumerate(operands):
                if opr.getType() != triton.OPERAND.MEM:
                    continue

                # check if a register is clobbered by the load
                clobber = None
                if first_clobber and operands[0].getType() == triton.OPERAND.REG:
                    clobber = operands[0]

                base = opr.getBaseRegister()
                index = opr.getIndexRegister()

                if clobber and ((base and clobber.isOverlapWith(base)) or (index and clobber.isOverlapWith(index.getId()))):
                    # watchpoint hit depends on clobbered register
                    # cannot determine the actual load access
                    candidates_clobber.append(pc)
                    continue

                disp = opr.getDisplacement()
                scale = opr.getScale()

                bits = disp.getBitSize()
                base = loader.ctx.getConcreteRegisterValue(base) if base.getId() != 0 \
                    else triton.Immediate(0, bits)
                index = loader.ctx.getConcreteRegisterValue(index) if index.getId() != 0 \
                    else triton.Immediate(0, bits)

                addr = (base + (index.getValue() * scale.getValue()) + disp.getValue()) \
                    % (2**bits-1)

                if addr >= wp and addr < wp+wp_size:
                    return pc

                # NOTE: if we get here, the load didn't resolve to the WP; we need
                # to investigate if this pred. could be viable still and under what
                # circumstances.

            # In absence of a perfect match, we prefer clobbers, and then bad matches
            return next(chain(candidates_clobber, candidates_badaddr), None)

    return None


def is_non_relative_store_hit(loader, insn):
    if is_relative_add_sub(loader, insn):
        return False
    ID = triton.OPCODE.X86
    if insn.getType() in (ID.CMP, ID.TEST):
        return False
    operands = insn.getOperands()
    if len(operands) > 1:
        lhs = operands[0]
        rhs = operands[1]
        return lhs.getType() == triton.OPERAND.MEM and rhs.getType() != triton.OPERAND.MEM
    else:
        return False

def is_relative_add_sub(loader, insn):
    ID = triton.OPCODE.X86
    operands = insn.getOperands()
    itype = insn.getType()
    if len(operands) > 1:
        lhs = operands[0]
        rhs = operands[1]
        if lhs.getType() == triton.OPERAND.MEM and (itype == ID.SUB or itype == ID.ADD):
            return rhs.getType() == triton.OPERAND.IMM
    return False

def rhs_clobbers_lhs(loader, insn):
    operands = insn.getOperands()
    first_clobber = len(operands) > 1

    if not first_clobber:
        return False

    lhs = operands[0]
    rhs = operands[1]

    if rhs.getType() != triton.OPERAND.MEM:
        return False

    # check if a register is clobbered by the load
    clobber = None
    if lhs.getType() == triton.OPERAND.REG:
        clobber = lhs
    else:
        return False

    # expand the clobber => get all regs

    # expands these too
    base = rhs.getBaseRegister()
    index = rhs.getIndexRegister()

    if clobber.isOverlapWith(base):
        return True

    if clobber.isOverlapWith(index):
        return True

    return False


def simple_clobbers_lhs(loader, insn):
    lhs = insn.getOperands()[0]
    rhs = insn.getOperands()[1]

    # expands these too
    base = rhs.getBaseRegister()
    index = rhs.getIndexRegister()

    if lhs.isOverlapWith(base):
        if index.getSize() == 0 and rhs.getDisplacement().getValue() == 0:
            # simple; just a register to restore; might have to subtract disp!
            return base

    if lhs.isOverlapWith(index):
        if base.getSize() == 0 and rhs.getScale().getValue() == 0:
            # simple; just a register to restore
            return index

    return None


def reset_engines(loader):
    """
    Reset the assumptions about tainted and symbolic memory and registers.
    """
    for m in loader.ctx.getTaintedMemory():
        loader.ctx.untaintMemory(m)
    for r in loader.ctx.getTaintedRegisters():
        loader.ctx.untaintRegister(r)

    loader.ctx.concretizeAllMemory()
    loader.ctx.concretizeAllRegister()


def model_as_list(model):
    xs = []
    for var_model in model.values():
        var = var_model.getVariable()
        if var.getType() != triton.SYMBOLIC.MEMORY_VARIABLE:
            continue
        addr = var.getOrigin()
        size = round(var.getBitSize() / 8)
        value = var_model.getValue()
        xs.append({
            "address": addr,
            "size": size,
            "value": value,
        })
    return xs


def ast_set_bytes(astctx, n, val):
    bits = n * 8
    m = val.getBitvectorSize() // 8
    base = []
    for _ in range(n - m):
        base.append(astctx.bv(0, 8))
    base.append(val)
    return astctx.concat(base)


def undo_load(loader, insn, wp_addr, init=None):
    lhs = insn.getOperands()[0]
    rhs = insn.getOperands()[1]

    # TODO: for mov, check if load is straight load from WP

    if rhs.getType() != triton.OPERAND.MEM:
        return None

    if lhs.getType() != triton.OPERAND.REG:
        # TODO: see if we can do MEM, MEM
        # TODO: handle the case of, e.g., cmp [mem], reg
        return None

    base = rhs.getBaseRegister()
    index = rhs.getIndexRegister()

    actx = init.ctx if init is not None else loader.ctx.getAstContext()

    model = None

    if lhs.isOverlapWith(base) and lhs.isOverlapWith(index):
        # index and base are unknown, but are part of same reg. (simple: eax, eax, or eax, rax)
        assert(base == index)
        assert(base.getBitSize() == index.getBitSize()) # may need to support this

        if init is None:
            basev = loader.ctx.newSymbolicVariable(base.getBitSize(), "BASE_INDEX_REG")

            baseast = actx.variable(basev)
            indexast = actx.variable(basev)
        else:
            basev = init.var

            baseast = init.ast
            indexast = init.ast

        bits = loader.ctx.getGprBitSize()

        wp_addrbv = actx.bv(wp_addr, bits)

        scale = rhs.getScale()
        scalev = actx.bv(scale.getValue(), scale.getBitSize())
        disp = rhs.getDisplacement()
        dispv = actx.bv(disp.getValue(), disp.getBitSize())

        query = actx.land([
            actx.equal(baseast, indexast),
            actx.equal(wp_addrbv, actx.bvadd(actx.bvadd(baseast, actx.bvmul(indexast, scalev)), dispv))
        ])

        if init is not None:
            query = actx.land([query, init.query])

        model = loader.ctx.getModel(query)

        return {base: model[basev.getId()].getValue()}

    elif lhs.isOverlapWith(base):
        if init is None:
            # unknown is base
            basev = loader.ctx.newSymbolicVariable(base.getBitSize(), "BASE_REG")
            baseast = actx.variable(basev)
        else:
            basev = init.var
            baseast = init.ast

        bits = loader.ctx.getGprBitSize()

        indexbv = actx.bv(0, bits)
        if index.getSize() != 0:
            indexbv = actx.bv(loader.ctx.getConcreteRegisterValue(index), index.getBitSize())

        wp_addrbv = actx.bv(wp_addr, bits)

        scale = rhs.getScale()
        scalev = actx.bv(scale.getValue(), scale.getBitSize())
        disp = rhs.getDisplacement()
        dispv = actx.bv(disp.getValue(), disp.getBitSize())

        query = actx.equal(wp_addrbv, actx.bvadd(actx.bvadd(baseast, actx.bvmul(indexbv, scalev)), dispv))

        if init:
            query = actx.land([query, init.query])

        model = loader.ctx.getModel(query)

        return {base: model[basev.getId()].getValue()}

    elif lhs.isOverlapWith(index):
        # unknown is index
        if init is None:
            indexv = loader.ctx.newSymbolicVariable(index.getBitSize(), "INDEX_REG")
            indexast = actx.variable(indexv)
        else:
            indexv = init.var
            indexast = init.ast

        bits = loader.ctx.getGprBitSize()

        basebv = actx.bv(0, bits)
        if base.getSize() != 0:
            basebv = actx.bv(loader.ctx.getConcreteRegisterValue(base), index.getBitSize())

        wp_addrbv = actx.bv(wp_addr, bits)

        scale = rhs.getScale()
        scalev = actx.bv(scale.getValue(), scale.getBitSize())
        disp = rhs.getDisplacement()
        dispv = actx.bv(disp.getValue(), disp.getBitSize())

        query = actx.equal(wp_addrbv, actx.bvadd(actx.bvadd(basebv, actx.bvmul(indexast, scalev)), dispv))

        if init:
            query = actx.land([query, init.query])

        model = loader.ctx.getModel(query)

        return {index: model[indexv.getId()].getValue()}

    # otherwise, no overlap; index and base are set in registers.
    return model


def undo_rep_insn(loader, insn):
    ID = triton.OPCODE.X86
    PREFIX = triton.PREFIX.X86

    model = dict()
    operands = insn.getOperands()

    prefix = insn.getPrefix()
    is_rep = prefix in (PREFIX.REP, PREFIX.REPE, PREFIX.REPNE)
    if is_rep:
        cx = loader.ctx.registers.ecx if loader.ctx.getGprSize() == 32 else loader.ctx.registers.rcx
        cx_val = loader.ctx.getConcreteRegisterValue(cx)
        flags = {
            PREFIX.REPE: {loader.ctx.registers.zf: 1, cx: cx_val+1},
            PREFIX.REPNE: {loader.ctx.registers.zf: 0, cx: cx_val+1},
            PREFIX.REP: {cx: cx_val+1},
        }
        model = flags[prefix]

    df = loader.ctx.getConcreteRegisterValue(loader.ctx.registers.df)
    if df == 0:  # do the reverse; DF=1 means decrement
        shifted = -1
    else:
        shifted = 1

    src = operands[1]
    dst = operands[0]

    reg = src.getBaseRegister()
    reg_val = loader.ctx.getConcreteRegisterValue(reg)
    model[reg] = reg_val + src.getSize() * shifted

    if insn.getType() in (ID.MOVSB, ID.MOVSW, ID.MOVSD, ID.MOVSQ):
        reg = dst.getBaseRegister()
        reg_val = loader.ctx.getConcreteRegisterValue(reg)
        model[reg] = reg_val + dst.getSize() * shifted

    return model


def undo_clobbers(loader, insn, wp_addr):
    ID = triton.OPCODE.X86

    opc = insn.getType()
    if opc in (ID.LODSB, ID.LODSW, ID.LODSD, ID.LODSQ, ID.MOVSB, ID.MOVSW, ID.MOVSD, ID.MOVSQ):
        return undo_rep_insn(loader, insn)

    operands = insn.getOperands()
    if len(operands) != 2:
        return None

    if opc in (ID.CMP, ID.TEST):
        # eqv. NOP
        return None

    lhs = operands[0]
    rhs = operands[1]

    if lhs.getType() != triton.OPERAND.REG:
        # TODO: handle the case of MEM
        return None
    if rhs.getType() != triton.OPERAND.MEM:
        return None

    clobbers = undo_load(loader, insn, wp_addr)

    ast = loader.ctx.getAstContext()
    bits = loader.ctx.getGprBitSize()

    if opc in (ID.MOV, ID.MOVZX, ID.MOVSX, ID.MOVSXD):
        return clobbers

    lhsbv = ast.bv(loader.ctx.getConcreteRegisterValue(lhs), lhs.getBitSize())
    rhsbv = ast.bv(loader.ctx.getConcreteMemoryValue(triton.MemoryAccess(wp_addr, rhs.getSize())), rhs.getBitSize())
    unkv = loader.ctx.newSymbolicVariable(lhs.getBitSize(), "LHS")
    unkvast = ast.variable(unkv)

    # maybe we can add more
    opmap = {
        ID.ADD: ast.bvadd,
        ID.AND: ast.bvand,
        ID.SAR: ast.bvashr,
        ID.OR: ast.bvor,
        ID.SHL: ast.bvshl,
        ID.SHR: ast.bvlshr,
        ID.SUB: ast.bvsub,
        ID.XOR: ast.bvxor,
    }

    if opc in opmap:
        bvop = opmap[opc]
        query = ast.equal(lhsbv, bvop(unkvast, rhsbv))
        if clobbers is not None:
            # CASE: e.g., add eax, [eax+edx]
            # NOTE: we need to add a constraint to the load clobbers and recompute
            clobbers = undo_load(loader, insn, wp_addr, init=ClobberQuery(ast, unkv, unkvast, query))
        else:
            # CASE: e.g., add eax, [edx*4]
            model = loader.ctx.getModel(query)
            clobbers = {lhs: model[unkv.getId()].getValue()}
    else:
        logger.warn("potentially unhandled undo operations: {}".format(insn))

    return clobbers


def get_load_size(insn, wp_size):
    ID = triton.OPCODE.X86

    operands = insn.getOperands()
    if len(operands) != 2:
        return wp_size  # no idea; use default

    opc = insn.getType()
    if opc in (ID.CMP, ID.TEST):
        # it could be either operand; find the memory load
        for op in operands:
            if op.getType() == triton.OPERAND.MEM:
                return op.getSize()
        return wp_size

    src = operands[1]
    if src.getType() == triton.OPERAND.MEM:
        return src.getSize()

    return wp_size


def analyse(loader, binary, wp, wp_size, load_pc, window, registers, assumed_ranges, check_val, permit_self_writes):
    """
    Performs analysis on the given watchpoint hit.

    The algorithm proceeds as follows:

    TODO
    """
    global EXP_VALUE
    global LOAD_B4_STORE
    
    rep_log_wp = assumed_ranges.at(wp).pop().data
    
    logger.info("analysing watchpoint hit %#x" % load_pc)
    
    if check_val and LOAD_B4_STORE == False:
        logger.info("There was a non-relative STORE before any loads of the watched memory, ignoring this hit.")
        return None

    orig_window = window

    binary_name = binary[0]
    binary = binary[1]

    blk = next(iter(binary.blocks.at(load_pc)))
    pc = blk.begin

    if load_pc == blk.begin:
        # case of jump to
        n_pc = resolve_jmp_pred(loader, binary, wp, wp_size, blk)
        if n_pc is not None:
            pc = n_pc
            logger.info("stepped back to block end at %#x next is WP hit" % pc)
        else:
            logger.warn(
                "watchpoint hit appears to be a jump target; cannot determine origin pc"
            )

            # NOTE: We should report an error here.
            return None
    else:
        # we got a hit in the same block, so we attempt to get the
        # instruction that caused the WP hit.
        logger.info("stepped back to block start at %#x next is WP hit" % pc)
        opc = loader.ctx.getConcreteMemoryAreaValue(pc, 16)
        insn = triton.Instruction()
        insn.setOpcode(opc)
        insn.setAddress(pc)
        loader.ctx.disassembly(insn)
        
        max_window = 512

        while insn.getNextAddress() != load_pc:
            max_window-=1
            if max_window <= 0:
                logger.info("Failed to step from block start to watchpoint hit PC, aborting.")
                return None
            pc = insn.getNextAddress()
            opc = loader.ctx.getConcreteMemoryAreaValue(pc, 16)
            insn = triton.Instruction()
            insn.setOpcode(opc)
            insn.setAddress(pc)
            loader.ctx.disassembly(insn)
            logger.debug("stepping... %#x" % pc)

    # execute the load; see NOTE below, why we must do this.
    opc = loader.ctx.getConcreteMemoryAreaValue(pc, 16)
    insn = triton.Instruction()
    insn.setOpcode(opc)
    insn.setAddress(pc)
    loader.ctx.disassembly(insn)

    real_wp_hit = pc

    if is_non_relative_store_hit(loader, insn):
            
        logger.debug("WP hit appears to be a store, not a load: {}".format(insn))
        
        # If value checking is enabled, and LOAD_B4_STORE is unset
        if check_val:
            if LOAD_B4_STORE is None:
                # The first hit in the session was a store
                # so we will ignore future hits in the same session
                LOAD_B4_STORE = False
            else:
                # Watchpoint has a new value, so don't check future values in session
                EXP_VALUE = None
        
        return None
    
    elif LOAD_B4_STORE is None: 
        # We have read of the watchpoint mem before storing any new values
        # So we can check future values
        LOAD_B4_STORE = True
    
    if EXP_VALUE:
        wp_val = loader.ctx.getConcreteMemoryAreaValue(wp, wp_size)
        wp_val_b64 = base64.b64encode(wp_val).decode("utf-8")
        
        if wp_val_b64 != EXP_VALUE:
            logger.debug("value at watchpoint different to expected, not state defining")
            return None

    # NOTE: only construct a variable for the WP memory once
    wp_iv = Interval(wp, wp+wp_size)
    if wp_iv in assumed_ranges:
        assumed_ranges.remove(wp_iv)
        
    # get estimate of WP size; this will be later reflected in the model output
    wp_size = get_load_size(insn, wp_size)
    wp_sym = loader.ctx.symbolizeMemory(triton.MemoryAccess(wp, wp_size))
    wp_sym.setAlias("WP")

    for iv in assumed_ranges:
        start_addr = iv.begin
        length = iv.end - iv.begin
        access = triton.MemoryAccess(start_addr, length)
        # TODO: make access aligned -> this should be OK?
        loader.ctx.symbolizeMemory(access)


    undos = undo_clobbers(loader, insn, wp)
    if undos is not None:
        for reg, val in undos.items():
            logger.debug("restoring {} to {:x}".format(reg.getName(), val))
            loader.ctx.setConcreteRegisterValue(reg, val)

    try:
        # re-execute the instruction: no clobbers to lhs from rhs from load
        loader.ctx.processing(insn)
    except TypeError as e:
        logger.debug(e)
        return None
        
    logger.info("setting up taint on accesses")

    # introduce taint;
    for (load, _) in insn.getLoadAccess():
        loader.ctx.setTaintMemory(load, True)
    for (store, _) in insn.getStoreAccess():
        loader.ctx.setTaintMemory(store, True)
    for (reg, _) in insn.getWrittenRegisters():
        if reg not in (IP, SP):
            loader.ctx.setTaintRegister(reg, True)

    pc = load_pc

    call_depth = 0
    dependency = None

    logger.info("propagating taint to next local branch")
    while pc and window > 0:
        opc = loader.ctx.getConcreteMemoryAreaValue(pc, 16)

        insn = triton.Instruction()
        insn.setOpcode(opc)
        insn.setAddress(pc)

        try:
            loader.ctx.processing(insn)
        except TypeError as e:
            logger.debug(e)
            return None
        
        logger.info("taint to %s via %s" % (hex(insn.getAddress()), insn))
        
        # NOTE: handle stubbed functions; see stubs.py
        stubbed = False
        try:
            stubbed = handle_stubbed(loader, insn.getAddress())
        except stubs.Exited as ex:
            logger.info(str(ex))
            return None
        except stubs.NeedsInput as ex:
            logger.info(str(ex))
            return None

        if stubbed:
            pc = loader.ctx.getConcreteRegisterValue(IP)
            window -= 1
            continue
        # HEURISTIC: real logic decisions are made in higher level functions
        # e.g., do not report the comparison inside a strcmp(., .), but do report
        # the control-flow dependent on its return value
        #
        # e.g., does the return value depend on the hit value and then influence
        # a decision in the caller of this function
        elif insn.isBranch() and insn.isTainted() and call_depth <= 0 and \
            (insn.getType() not in UNCOND_JMPS or insn.getOperands()[0].getType() == triton.OPERAND.REG):
                logger.info("reached intraprocedural control-flow; "
                            "recording dependency information")
                dependency = insn
                break

        # NOTE: this will now allow us to follow interprocedural control-flow;
        # it remains a question if we should then make a stack to decide if we
        # should treat the next branch as something we want to terminate the
        # above check on. NOTE: needs testing.
        elif insn.getType() == triton.OPCODE.X86.HLT:
            # here we would diverge into non-localised control flow
            logger.warn(
                "reached interprocedural control-flow; aborted analysis")
            return None
        elif insn.getType() == triton.OPCODE.X86.CALL:
            call_depth += 1
        elif insn.getType() in (triton.OPCODE.X86.RET, triton.OPCODE.X86.IRET):
            call_depth -= 1

        pc = loader.ctx.getConcreteRegisterValue(IP)
        window -= 1

    if dependency is None:
        logger.warn("expended execution window in attempting to find "
                    "intraprocedural control-flow; aborted analysis")
        return None

    # already in branch, get address
    in_branch_addr = loader.ctx.getConcreteRegisterValue(IP)

    pco = loader.ctx.getPathConstraints()

    if len(pco) == 0:
        # this branch must have been a control dependency
        logger.info("at: {:x}".format(in_branch_addr))
        return None

    this_constrs = pco[-1]
    # Assume binary choice
    if not this_constrs.isMultipleBranches(): # this is the only case we really care about
        # TODO: likely we should just explore this one?
        logger.warn("dependent branch has only a single target?")
        return None

    br1v = this_constrs.getBranchConstraints()[0]
    br2v = this_constrs.getBranchConstraints()[1]

    taken, not_taken = (br1v, br2v) if br1v["isTaken"] else (br2v, br1v)

    # Check what the concrete flow did
    this, other = (taken, not_taken) if in_branch_addr == taken["dstAddr"] else (not_taken, taken)

    this_constr = this["constraint"]
    other_constr = other["constraint"]

    # Does either branch depend on other assumed state memory?
    thism = loader.ctx.getModel(loader.ctx.getPathPredicate())

    # Get negated on the immediate branch
    loader.ctx.popPathConstraint()
    loader.ctx.pushPathConstraint(other_constr)
    otherm = loader.ctx.getModel(loader.ctx.getPathPredicate())

    if len(thism) > 1 or len(otherm) > 1:
        # We depend on more than just this hit to get here.
        logger.warn("branch target is not independent of other state memory")

    output = {
        "branch_model_taken": model_as_list(thism),
        "branch_model_not_taken": model_as_list(otherm),
    }

    ## NOTE: we can check if WP is in the models

    logger.debug("this model: " +  " ".join("{:x} ({} bytes) = {:x}".format(v["address"], v["size"], v["value"]) for v in model_as_list(thism)))
    logger.debug("other model: " + " ".join("{:x} ({} bytes) = {:x}".format(v["address"], v["size"], v["value"]) for v in model_as_list(otherm)))

    # get merge point
    merges = compute_branch_merge(binary, taken["dstAddr"], not_taken["dstAddr"])

    has_state = False
    for model_id, dst, model in zip(("taken", "not_taken"), (taken["dstAddr"], not_taken["dstAddr"]), (thism, otherm)):
        logger.info("testing model: {}".format(model_id))
        if dst in merges:
            logger.debug("skipping branch at {:x}; is a merge point".format(dst))
            continue
        reset_engines(loader)
        # reset state
        set_state(loader, (binary_name, binary), registers)

        # symbolise all assumed ranges
        for iv in assumed_ranges:
            start_addr = iv.begin
            length = iv.end - iv.begin
            access = triton.MemoryAccess(start_addr, length)
            # TODO: make access aligned (see above)
            loader.ctx.symbolizeMemory(access)

        # concretise ranges based on models
        for var_model in model.values():
            var = var_model.getVariable()
            if var.getType() == triton.SYMBOLIC.MEMORY_VARIABLE:
                address = var.getOrigin()
                length = round(var.getBitSize() / 8)
                access = triton.MemoryAccess(address, length)
                value = var_model.getValue()
                logger.debug("setting {:x} to {:x}".format(address, value))
                loader.ctx.setConcreteMemoryValue(access, value)
            elif var.getType() == triton.SYMBOLIC.REGISTER_VARIABLE:
                register = var.getOrigin()
                value = var_model.getValue()
                loader.ctx.setConcreteRegisterValue(loader.ctx.getRegister(register), value)

        pc = real_wp_hit
        opc = loader.ctx.getConcreteMemoryAreaValue(pc, 16)
        insn = triton.Instruction()
        insn.setOpcode(opc)
        insn.setAddress(pc)
        loader.ctx.disassembly(insn)

        undos = undo_clobbers(loader, insn, wp)
        if undos is not None:
            for reg, val in undos.items():
                logger.debug("restoring {} to {:x}".format(reg.getName(), val))
                loader.ctx.setConcreteRegisterValue(reg, val)
                
        try:
            loader.ctx.processing(insn)
        except TypeError as e:
            logger.debug(e)
            return None

        # first we run until the branch
        pc = load_pc
        while pc != dependency.getAddress():
            opc = loader.ctx.getConcreteMemoryAreaValue(pc, 16)
            insn = triton.Instruction()
            insn.setOpcode(opc)
            insn.setAddress(pc)
            try:
                loader.ctx.processing(insn)
            except TypeError as e:
                logger.debug(e)
                return None
            logger.debug("stepping to branch %s via %s" % (hex(insn.getAddress()), insn))
            handle_stubbed(loader, pc)
            pc = loader.ctx.getConcreteRegisterValue(IP)

        # run branch
        opc = loader.ctx.getConcreteMemoryAreaValue(pc, 16)
        insn = triton.Instruction()
        insn.setOpcode(opc)
        insn.setAddress(pc)
        try:
            loader.ctx.processing(insn)
        except TypeError as e:
            logger.debug(e)
            return None
        handle_stubbed(loader, pc)

        window = orig_window

        skip = False
        is_ret = False
        call_depth = 0

        while not skip and window > 0 and pc not in merges and not is_ret:
            # run via branch until:
            #    1) window depletion
            #    2) hit merge

            pc = loader.ctx.getConcreteRegisterValue(IP)
            opc = loader.ctx.getConcreteMemoryAreaValue(pc, 16)

            insn = triton.Instruction()
            insn.setAddress(pc)
            insn.setOpcode(opc)
            
            try:
                loader.ctx.processing(insn)
            except TypeError as e:
                logger.debug(e)
                return None

            logger.debug("stepping to merge/window depletion %s " % hex(insn.getAddress()))
            
            stubbed = False
            try:
                stubbed = handle_stubbed(loader, pc)
            except stubs.Exited as ex:
                logger.info(str(ex))
                skip = True
                # reached nothing.
                output["branch_" + model_id] = None
                logger.debug("stub exception")
                break
            except stubs.NeedsInput as ex:
                skip = True
                # TODO: allow this to be distinguished from STORE kind
                logger.debug("state memory as STUB NEEDS INPUT")
                has_state = True
                output["branch_" + model_id] = {
                    "pre_merge": True,
                    "model": model_as_list(loader.ctx.getModel(loader.ctx.getPathPredicate())),
                    "store_address": -1,
                    "store_size": 0,
                    "store_pc": -1
                }
                logger.debug("stub needs input")
                break
            if insn.getType() == triton.OPCODE.X86.CALL:
                call_depth += 1
            if insn.getType() in (triton.OPCODE.X86.RET, triton.OPCODE.X86.IRET):
                call_depth -= 1

            if stubbed:
                window -= 1
                continue

            if insn.getType() in (triton.OPCODE.X86.RET, triton.OPCODE.X86.IRET):
                if call_depth <= 0:
                    is_ret = True
                window -= 1
                continue

            if insn.getType() == triton.OPCODE.X86.HLT:
                skip = True
                # reached nothing.
                output["branch_" + model_id] = None
                logger.debug("reached halt instruction")
                break

            stores = insn.getStoreAccess()
            for (acc, _) in chain(insn.getLoadAccess(), stores):
                addr = acc.getAddress()
                size = acc.getSize()
                
                if addr == wp and not permit_self_writes:
                    logger.debug("memory influenced conditional write to itself before merge, continuing...")
                    break
                
                if addr == wp or (assumed_ranges.overlaps(addr, addr + size) and acc in [store[0] for store in stores]):
                    skip = True
                    has_state = True
                    mapped_store_addr_sm = None
                    if addr == wp:
                        mapped_store_addr_sm = rep_log_wp
                    else:
                        mapped_store_addr_sm = assumed_ranges[addr:addr+size].pop().data
                    logger.debug("state memory as PRE-MERGE CONDITIONAL WRITE to {" + str(hex(mapped_store_addr_sm[0]) + ", " + str(hex(mapped_store_addr_sm[2])))+"}")
                    output["branch_" + model_id] = {
                        "pre_merge": True,
                        "model": model_as_list(loader.ctx.getModel(loader.ctx.getPathPredicate())),
                        "store_address": mapped_store_addr_sm[0]+mapped_store_addr_sm[2],
                        "store_size": size,
                        "store_pc": insn.getAddress()
                    }
                    break
                if skip: break
                # taint memory accessed to see if it later used within a merged flow
                loader.ctx.setTaintMemory(acc, True)
            window -= 1
            
        if window <= 0:
            logger.debug("depleted window searching for merge point")

        if is_ret:
            logger.debug("hit return searching for merge point")
            
        if pc in merges:
            logger.debug("reached merge point")

        while not skip and window > 0:
            # we only enter this if we're in a merge, otherwise we'd have already returned
            pc = loader.ctx.getConcreteRegisterValue(IP)
            opc = loader.ctx.getConcreteMemoryAreaValue(pc, 16)

            insn = triton.Instruction()
            insn.setAddress(pc)
            insn.setOpcode(opc)
            
            try:
                loader.ctx.processing(insn)
            except TypeError as e:
                logger.debug(e)
                return None
            
            logger.debug("stepping after merge to %s " % hex(insn.getAddress()))

            stubbed = False
            try:
                stubbed = handle_stubbed(loader, pc)
            except stubs.Exited as ex:
                logger.info(str(ex))
                skip = True
                # reached nothing.
                output["branch_" + model_id] = None
                break
            except stubs.NeedsInput as ex:
                logger.info(str(ex))
                skip = True
                output["branch_" + model_id] = None
                break

            if stubbed:
                window -= 1
                continue

            if insn.getType() == triton.OPCODE.X86.HLT:
                skip = True
                # reached nothing.
                output["branch_" + model_id] = None
                break

            for (acc, _) in insn.getStoreAccess():
                addr = acc.getAddress()
                size = acc.getSize()
                # TODO(slt): no taint here???
                if addr == wp or addr == assumed_ranges.overlaps(addr, addr + size) and insn.isTainted():
                    has_state = True
                    mapped_store_addr_sm = None
                    if addr == wp:
                        mapped_store_addr_sm = rep_log_wp
                    else:
                        mapped_store_addr_sm = assumed_ranges[addr:addr+size].pop().data
                    logger.debug("state memory as POST-MERGE TAINTED WRITE to {" + str(hex(mapped_store_addr_sm[0]) + ", " + str(hex(mapped_store_addr_sm[2])))+"}")
                    output["branch_" + model_id] = {
                        "pre_merge": False,
                        "model": model_as_list(loader.ctx.getModel(loader.ctx.getPathPredicate())),
                        "store_address": mapped_store_addr_sm[0]+mapped_store_addr_sm[2],
                        "store_size": size,
                        "store_pc": insn.getAddress(),
                    }
                    # OK, accesses assumed state memory and the access was performed
                    # dependent upon previously tainted memory
                    skip = True
                    break
            window -= 1

    return output if has_state else None


def load_binary(ida_path, bin_path):
    """
    Loads the binary at bin_path using IDA Pro at ida_path
    """
    logger.info("loading binary from %s using IDA Pro at %s" %
                (bin_path, ida_path))
    return ida_loader(ida_path, bin_path)


def init_context(binary, registers, stack, heap, segments, ext_ranges, data_tracker = False):
    """
    Initialises the Triton context. Sets IP and SP to alias the
    corresponding registers for the architecture of the analysed
    binary.
    """
    global IP, SP, RET, WORD_SIZE

    binary_name = binary[0]
    binary = binary[1]

    if binary.arch == "metapc":
        if binary.bits == 32:
            arch = triton.ARCH.X86
        else:  # binary.bits == 64
            arch = triton.ARCH.X86_64
    else:
        logger.critical('unsupported architecture')
        sys.exit(-1)

    stack_s = LoadableSection(backing=stack.content,
                              vaddress=stack.virtual_address,
                              vsize=len(stack.content),
                              offset=0,
                              size=len(stack.content))
    heap_s = LoadableSection(backing=heap.content,
                             vaddress=heap.virtual_address,
                             vsize=len(heap.content),
                             offset=0,
                             size=len(heap.content))
    segments = [LoadableSection(backing=segment.content,
                                vaddress=segment.virtual_address,
                                vsize=len(segment.content),
                                offset=0,
                                size=len(segment.content))
                for segment in segments]

    logger.info('initialising new context')

    if data_tracker:
        heap_ranges = (heap.virtual_address, heap.virtual_address+len(heap.content))
        loader = DataTrackerLoader(DumpLoader(arch, *chain((stack_s, heap_s), segments)), heap_ranges) # for now supply no suspected ranges
    else:
        loader = ZzzLoader(DumpLoader(arch, *chain((stack_s, heap_s), segments)))

    if arch == triton.ARCH.X86:
        IP = loader.ctx.registers.eip
        SP = loader.ctx.registers.esp
        RET = loader.ctx.registers.eax
        WORD_SIZE = triton.CPUSIZE.DWORD
    else:
        IP = loader.ctx.registers.rip
        SP = loader.ctx.registers.rsp
        RET = loader.ctx.registers.rax
        WORD_SIZE = triton.CPUSIZE.QWORD

    set_state(loader, (binary_name, binary), registers)

    return loader


def read_binary(base, path, name, perms=None):
    """
    Read a dumped region from the given path
    """
    with open(path, "rb") as f:
        return MemoryRegion(base, bytes(f.read()), name, perms)


def read_registers(path):
    """
    Read the dumped register values from the given path
    """
    with open(path, "r") as f:
        return [Register(REG_MAP[r["name"]], r["value"]) for r in json.load(f)]


def read_meta(prefix):
    """
    Read the meta information from the log specified by prefix.
    """
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
        segments = [read_binary(s["low"], s["dump"], s["name"], s["perms"]) for s in jsn["segments"]]
        return (malloc_log, watchpoint, orig_watchpoint, wp_size, pc, stack_base, heap_base, registers, segments)


def compute_cfg_merges(cfg, entry, p1, p2):
    """
    Compute the intersection of the decendants of the two block
    addresses p1 and p2.
    """
    df = nx.dominance_frontiers(cfg, entry)
    dfp1 = df[p1].union({p1})
    dfp2 = df[p2].union({p2})
    return dfp1.intersection(dfp2)


def compute_branch_merge(binary, branch_target1, branch_target2):
    """
    Compute the merge point of flows out of the block containing branch_address
    where one of those flows contains branch_target.
    """
    blk = next(iter(binary.blocks.at(branch_target1)))
    entry = blk.data["function"]["address"]
    cfg = build_cfg(blk.data["function"])

    return compute_cfg_merges(cfg, entry, branch_target1, branch_target2)


def find_binary(segment, binaries):
    """
    Find the given binaries corresponding to the given segment (MemoryRegion).
    """
    name = path.basename(segment.file)
    return next((n, b) for n, b in binaries.items() if path.basename(n) == name)


def main():
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
    cli.add_argument("--data-tracker",
                     help="enable data type inference tracking",
                     default=False,
                     action="store_true")
    cli.add_argument("--extended",
                     help="perform extended analysis using ranges in file",
                     required=True,
                     type=str)
    cli.add_argument("--repr-mallocs",
                     help="representative malloc log to align watchpoint mallocs against",
                     default=None,
                     type=str)
    cli.add_argument("--exp-value",
                     help="the expected value at the read watchpoint hit",
                     default=None,
                     type=str)
    cli.add_argument("--self-write",
                     help="the expected value at the read watchpoint hit",
                     default=False,
                     action="store_true")
    

    args = cli.parse_args()
    logging.basicConfig(level=logging.DEBUG,format="%(asctime)s (%(levelname)s): %(message)s",
                        handlers=[ logging.FileHandler(sorted(args.watchpoints)[0]+"_taint.log")])

    if args.debug:
        logger.addHandler(logging.StreamHandler())

    binaries = {name: load_binary(args.ida, name) for name in args.binaries}
    logger.info("binaries successfully loaded")
    
    json_output = []
    
    global EXP_VALUE
    global LOAD_B4_STORE
    
    if(args.exp_value):
        EXP_VALUE = args.exp_value
    
    for prefix in sorted(args.watchpoints):
        logger.info("Analysising watchpoint hit: " + prefix[prefix.rfind("/"):])
        # If this is the first watchpoint of the session, reset the expected value
        if "watchpoint-1" in prefix and args.exp_value:
            EXP_VALUE = args.exp_value
            LOAD_B4_STORE = None
            
        mallocs, wp, o_wp, wp_size, pc, sb, hb, registers, segments = read_meta(prefix)

        ext_ranges = None
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
                rep_sel = 1
            else:
                mapping = ma.build_mapping(repr_mallocs, this_mallocs)
                rep_sel = 0

            def translate(sm_entry, mapping, rep_sel):
                # sm_entry = rep log : (allocBase, allocSize, locOffset, locSize)
                mapped = next((x for x in mapping if 
                              (x[rep_sel][0].ret, x[rep_sel][0].size) == (sm_entry[0], sm_entry[1])), None)
                if not mapped: 
                    logger.debug("Failed to map state memory: " + str(sm_entry))
                    return None
                sm = mapped[0][0] if rep_sel else mapped[1][0]
                addr = sm.ret + sm_entry[2]
                return Interval(addr, addr+sm_entry[3], sm_entry)

            ext_ranges = IntervalTree()
            for v in map(lambda l: l.split(" "), xf.readlines()):
                sm_entry = tuple(map(int, v))
                intv = translate(sm_entry, mapping, rep_sel)
                if intv:
                    ext_ranges.add(intv)

        local_pc = False
        binary = None

        for i in range(len(segments)):
            if "x" in segments[i].perms:
                this_binary = find_binary(segments[i], binaries)

                # if this segment contains the WP hit PC
                if pc >= segments[i].virtual_address and pc < segments[
                        i].virtual_address + len(segments[i].content):
                    local_pc = True
                    binary = this_binary

                # rebase if the segment base in IDA doesn't match that
                # reported by the dumps of the corresponding segment
                if segments[i].virtual_address != this_binary[1].segment_base:
                    logger.info("rebasing {:x} from {:x}".format(segments[i].virtual_address, this_binary[1].segment_base))
                    this_binary[1].rebase(segments[i].virtual_address)

        if not local_pc:
            logger.warn("watchpoint is not contained within program owned "
                        "segment; likely in shared library code; skipping "
                        "analysis")
            continue

        stack = read_binary(sb, prefix + "_stack.dump", "stack")
        heap = read_binary(hb, prefix + "_heap.dump", "heap")

        loader = init_context(binary, registers, stack, heap, segments, ext_ranges, data_tracker=args.data_tracker)

        stateful = analyse(loader, binary, wp, wp_size, pc, args.window, registers, ext_ranges, args.exp_value is not None, args.self_write)
        json_output.append({
            "log_name": prefix+".log",
            "pc": pc,
            "watchpoint": wp,
            "orig_watchpoint": o_wp,
            "stateful": stateful is not None,
            "extended": stateful,
            "data_inference": loader.resolve_loads(for_ranges=ext_ranges) if args.data_tracker else None,
        })

    json.dump(json_output, sys.stdout)


if __name__ == "__main__":
    main()
