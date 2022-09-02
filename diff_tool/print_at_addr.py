import argparse
import os
import json
import sys
from itertools import groupby
from operator import itemgetter
from state_diff import group_by_io_type, load_logs

def print_at_addr(snaps, addr, size):

    for s in snaps:
        print(s)
        for s_i in s:
            fh = open(s_i, 'rb')
            fh.seek(int(addr, 0))
            fhv = fh.read(size)
            print(fhv.hex())

        print("\n\n")

if __name__ == "__main__":

    CLI=argparse.ArgumentParser()
    CLI.add_argument("--snaps", required=True, nargs='+')
    CLI.add_argument("--addr")
    CLI.add_argument("--size", type=int, default=1)
    args = CLI.parse_args()

    snap_metadata = load_logs(args.snaps)
    grouped_snaps = group_by_io_type(snap_metadata)
    print_at_addr(grouped_snaps, args.addr, args.size)
