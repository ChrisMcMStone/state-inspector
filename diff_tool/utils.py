import json
import re
import os
from itertools import groupby

POINTER_SIZE = 8

def is_pointer(test_bufs, mapped_ranges):
    if mapped_ranges is None: return False
    for buf in test_bufs:
        buf = bytearray(buf)
        for i in range(1, POINTER_SIZE+1):
            cp = int.from_bytes(buf[i:i+POINTER_SIZE], "little")
            for (mr_min, mr_max) in mapped_ranges:
                if cp >= mr_min and cp < mr_max:
                    return True
    return False


def parse_mem_maps(mem_maps_file):

    heap_base = 0x0
    mapped_ranges = []

    mf = open(mem_maps_file, 'r')
    for line in mf.readlines():  # for each mapped region
        m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
        if m.group(3) == 'r':  # if this is a readable region
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            mapped_ranges.append((start,end))
            if "heap" in line:
                heap_base = start
            
    mf.close()
    return heap_base, mapped_ranges
    
    
def load_logs(logs):

    snap_metadata = []

    for log in logs:
        with open(log, "r") as json_file:
            try:
                decoded = json.load(json_file)
                snap_metadata = snap_metadata + decoded
            except json.decoder.JSONDecodeError as err:
                continue

    return snap_metadata


def group_by_io_type(snaps, add_metadata, terminating_outputs):

    grouped_snaps = []
    done = []
    # TODO fix this group by hack
    for k,_ in groupby(snaps,key=lambda x: (x["inputs"], x["type"])):
        if k in done: continue
        grouped_snaps.append([(x if add_metadata else x["dump_file"]) for x in snaps if x["inputs"] == k[0] and x["type"] == k[1]])
        done.append(k)
    
    if terminating_outputs is None or len(terminating_outputs) == 0:
        return grouped_snaps
    
    # Now remove any snapshot groups which contain a terminating output which is not the last output of the associated output sequence.
    
    for gs in grouped_snaps:
        for to in terminating_outputs:
            o_list = gs[0]["outputs"]
            for i in range(len(o_list)):
                o = o_list[i]
                if to in o and i != (len(o_list) -1):
                    grouped_snaps.remove(gs)
                
    return grouped_snaps
