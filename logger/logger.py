import heapq
import argparse
import os.path
import time
import json

class Logger(object):
    LOG_EV_DUMP = "LOG_WRITE"
    LOG_EV_IN = "LOG_INPUT"
    LOG_EV_OUT = "LOG_OUTPUT"

    def __init__(self, path):
        self.handle = open(path, "w")

    def __del__(self):
        if not self.handle.closed:
            self.handle.close()

    def ok(self):
        return not bool(self.handle.errors)

    @staticmethod
    def get_time():
        return int(time.monotone() * 1000 * 1000 * 1000)

    def new_input_msg(self, m):
        self.handle.write("{} {} {}\n".format(get_time(),
                                            Logger.LOG_EV_IN,
                                            str(m)))

    def new_output_msg(self, m):
        self.handle.write("{} {} {}\n".format(get_time(),
                                            Logger.LOG_EV_OUT,
                                            str(m)))


class LogMerger(object):
    def __init__(self, root, ctrl_log, dump_log, out_log, malloc_log, zeroed):
        self.root = root
        self.ctrl_log = open(ctrl_log, "r")
        self.dump_log = open(dump_log, "r")
        self.meta_log = open(out_log, "w")
        self.malloc_log = malloc_log
        self.zeroed = zeroed == "1"

    def __del__(self):
        if not self.ctrl_log.closed:
            self.ctrl_log.close()
        if not self.dump_log.closed:
            self.dump_log.close()

    def _process_line_dump(self, line):
        line = line.replace("\n", "")
        line = line.split(" ", 5)
        if line[1] not in (Logger.LOG_EV_IN, Logger.LOG_EV_OUT, Logger.LOG_EV_DUMP):
            raise ValueError("unknown log message type: %s" % line[1])
        return (int(line[0]), line[1], line[2], line[3], int(line[4]))

    def _process_line_ctrl(self, line):
        line = line.replace("\n", "")
        line = line.split(" ", 3)
        if line[1] not in (Logger.LOG_EV_IN, Logger.LOG_EV_OUT, Logger.LOG_EV_DUMP):
            raise ValueError("unknown log message type: %s" % line[1])
        return (int(line[0]), line[1], line[2])

    # If we have a write_dump after a LOG_input or LOG_output, then either:
    # - our query interface didn't wait long enough for a output(s)
    # - the target didn't read our input because it was lost in transmission (so non-determinism detection)
    # For now we will detect this and flag. TODO handle properly for learner.

    def process(self):
        ndump_log = list(iter(self.dump_log))
        dump_log = []
        for (ev, nv) in zip(ndump_log, ndump_log[1:] + [None]):
            evp = self._process_line_dump(ev)
            if evp[3] == "SELECT":
                nvp = self._process_line_dump(nv)
                if nvp[3] == "WRITE":
                    new_evp = (evp[0], evp[1], evp[2], "READ", evp[4])
                    dump_log.append(new_evp)
            else:
                dump_log.append(evp)
        evs = list(heapq.merge(map(self._process_line_ctrl, iter(self.ctrl_log)), iter(dump_log), key=lambda v: v[0]))
        chain_inputs = []
        chain_outputs = []
        log = []

        # Don't start logging until first syscall after first input
        start_dump_logs = False

        # Stop logging dumps after last i/o log item
        last_io_log_item = None
        for ev in reversed(evs):
            if ev[1] == Logger.LOG_EV_IN or ev[1] == Logger.LOG_EV_OUT:
                last_io_log_item = ev
                break

        # Delay logging a memory dump until we know the corresponding output
        log_write_next_out = []
        
        # Keep track of whether a read has preceeded a write
        read_before_write = False
        
        has_logged_read = False

        for ev in evs:
            print(ev)
            # Log the last read
            if ev[1] == Logger.LOG_EV_DUMP and start_dump_logs:
                # This also means if there are consecutive writes, we consider only the last of those writes 
                # the snapshot for a given I/O sequence pair. 
                if "WRITE" in ev[3] or "CLOSE" in ev[3]:
                    # We don't know the final output sequence for the dump at this point, so log after EV_OUT
                    log_write_next_out = ev
                    # Check non-determinsm
                    if not read_before_write:
                        print("\nWARNING: Write snapshot before read of input. This could mean target sent two outputs to one input. Try adjusting test-harness timeout\n")
                if "READ" in ev[3] and not has_logged_read:
                    read_before_write = True
                    # This is the read for the incoming input which has yet to be processed, hence chain_inputs[:-1]
                    log_read = {"dump_file": ev[2], 
                                "inputs": list(chain_inputs[:-1]), 
                                "outputs": list(chain_outputs), 
                                "type": ev[3], "count": ev[4], 
                                "timestamp": ev[0],
                                "zeroed": 1 if self.zeroed else 0}
                    if self.malloc_log:
                        log_read["malloc_log"] = self.malloc_log
                    log.append(log_read)
                    has_logged_read = True
            elif ev[1] == Logger.LOG_EV_IN:
                chain_inputs.append(ev[2])
                start_dump_logs = True
                read_before_write = False
                has_logged_read = False
            elif ev[1] == Logger.LOG_EV_OUT and start_dump_logs:
                chain_outputs.append(ev[2])
                read_before_write = False
                if log_write_next_out:
                    log_item = {"dump_file": log_write_next_out[2],
                                "inputs": list(chain_inputs), 
                                "outputs": list(chain_outputs), 
                                "type": log_write_next_out[3], 
                                "count": log_write_next_out[4],
                                "timestamp": ev[0],
                                "zeroed": 1 if self.zeroed else 0}
                    if self.malloc_log:
                        log_item["malloc_log"] = self.malloc_log
                    log.append(log_item)
                    log_write_next_out = []
            if ev == last_io_log_item:
                break

        self.meta_log.write(json.dumps(log, indent=4))

if __name__ == "__main__":

    CLI=argparse.ArgumentParser()
    CLI.add_argument("--root", help="root directory where snapshots are stored", required=True)
    CLI.add_argument("--ctrl", help="input/output query log made by interface", required=True)
    CLI.add_argument("--dump", help="memory snapshot log", required=True)
    CLI.add_argument("--malloc", help="malloc log", required=False)
    CLI.add_argument("--out", help="output log", required=True)
    CLI.add_argument("--zeroed", help="is memory zeroed, if not it is 0xFF", required=True)
    args = CLI.parse_args()

    merger = LogMerger(args.root, args.ctrl, args.dump, args.out, args.malloc, args.zeroed)
    merger.process()
