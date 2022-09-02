import json
import subprocess
import tempfile
import os
from collections import namedtuple
from intervaltree import Interval, IntervalTree
from copy import deepcopy

LOADER_TMPL = """
from idaapi import *
from idautils import *
import json
import sys

# Adapted from keystone; see: https://github.com/keystone-engine/keypatch/blob/bfcaef11de3a90efb08ed4f0c39dccf40d5613d0/keypatch.py
def get_meta():
    binary_info = dict()
    info = idaapi.get_inf_structure()
    try:
        cpuname = info.procname.lower()
    except:
        cpuname = info.procName.lower()
    try:
        # since IDA7 beta 3 (170724) renamed inf.mf -> is_be()/set_be()
        is_be = idaapi.cvar.inf.is_be()
    except:
        # older IDA versions
        is_be = idaapi.cvar.inf.mf

    binary_info['arch'] = cpuname
    binary_info['bits'] = 64 if info.is_64bit() else 32
    binary_info['endian'] = 'Big' if is_be else 'Little'

    return binary_info


autoWait()
image = get_meta()
image['functions'] = []
image['segment_base'] = None #SegStart(MinEA())
image['imagebase'] = idaapi.get_imagebase()

for ea in Segments():
    if image['segment_base'] is None:
        base = SegStart(ea)
        if GetSegmentAttr(base, SEGATTR_PERM) & 1 == 1:
            image['segment_base'] = base
    for fn_entry_address in Functions(SegStart(ea), SegEnd(ea)):
        f = dict()
        f['address'] = fn_entry_address
        f['blocks'] = []
        fn = get_func(fn_entry_address)
        f['name'] = GetFunctionName(fn_entry_address)
        for fn_block in FlowChart(fn):
            block = dict()
            block['start_addr'] = fn_block.startEA
            block['end_addr'] = fn_block.endEA
            block['dests'] = []
            for block_succ in fn_block.succs():
                block['dests'].append(block_succ.startEA)
            f['blocks'].append(block)
        image['functions'].append(f)
with open('{}', 'w+') as f:
    json.dump(image, f)
Exit(0)
"""

class Image(object):
    def __init__(self, arch, bits, endian, segment_base, imagebase, blocks, functions):
        self.arch = arch
        self.bits = bits
        self.endian = endian
        self.orig_segment_base = segment_base
        self.segment_base = segment_base
        self.imagebase = imagebase
        self.blocks = blocks
        self.functions = functions


    def rebase(self, addr):
        self.blocks = IntervalTree(Interval(i.begin - self.segment_base + addr,
                                            i.end - self.segment_base + addr,
                                            { "dests": [d - self.segment_base + addr for d in i.data["dests"]],
                                              "function": i.data["function"] })
                                   for i in self.blocks.items())

        for fn in self.functions.values():
            fn["address"] = fn["address"] - self.segment_base + addr
            for block in fn["blocks"]:
                block["start_addr"] = block["start_addr"] - self.segment_base + addr
                block["end_addr"] = block["end_addr"] - self.segment_base + addr
                block["dests"] = [d - self.segment_base + addr for d in block["dests"]]

        self.segment_base = addr


def windowsify(path):
    if path.startswith('/'):
        path = 'Z:\\\\' + path[1:]
    path = path.replace('/', '\\\\')
    return path

def ida_loader(ida_path, binary, keep_database=True):
    f = tempfile.NamedTemporaryFile(suffix=".py", delete=False)
    jsn = tempfile.NamedTemporaryFile(suffix=".json", delete=False)

    f.write(LOADER_TMPL.format(jsn.name).encode("utf-8"))
    f.flush()
    f.close()

    if ida_path.endswith(".exe"):
        p = subprocess.Popen(["wine", ida_path, "-A", "-S" + windowsify(f.name), windowsify(binary)], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    else:
        env = os.environ
        env["TVHEADLESS"] = "1"
        p = subprocess.Popen([ida_path, "-A", "-S" + f.name, binary], env=env, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    p.wait()

    if not keep_database:
        idb = "{}.{}".format(binary, "i64" if ida_path.endswith("64.exe") or ida_path.endswith("64") else "idb")
        os.remove(idb)

    if p.returncode == 0:
        with open(jsn.name, "r") as jc:
            content = json.load(jc)
            # NOTE: IDA returns block bounds as [start_addr, end_addr)
            return Image(arch=content["arch"],
                         bits=content["bits"],
                         endian=content["endian"],
                         segment_base=content["segment_base"],
                         imagebase=content["imagebase"],
                         blocks = IntervalTree(Interval(b["start_addr"], b["end_addr"], {'dests': deepcopy(b["dests"]), 'function': fn})
                                               for fn in content["functions"]
                                               for b in fn["blocks"] if b["start_addr"] < b["end_addr"]),
                         functions = {fn["name"]: fn for fn in content["functions"]})
    else:
        return None
