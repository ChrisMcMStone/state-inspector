import argparse
import json
import sys


class Event(object):
    EV_SOCKET = 0
    EV_ACCEPT = 1
    EV_READ   = 2
    EV_WRITE  = 3
    EV_CLOSE  = 4


    def kind_str(self):
        if self.kind == Event.EV_SOCKET:
            return ("SOCKET", "POST(log,dump)")
        elif self.kind == Event.EV_ACCEPT:
            return ("ACCEPT", "PRE(log)/POST(dump)")
        elif self.kind == Event.EV_READ:
            return ("READ", "POST(log,dump)")
        elif self.kind == Event.EV_WRITE:
            return ("WRITE", "PRE(log)/POST(dump)")
        elif self.kind == Event.EV_CLOSE:
            return ("CLOSE", "PRE(log)/POST(dump)")


    def __init__(self, line):
        self.time, kind, *args = line.replace('\n', '').split(' ')
        if kind == "SOCKET":
            self.kind = Event.EV_SOCKET
            self.fd = int(args[0])
            self.typ = int(args[1]) # TODO: make symbol
        elif kind == "ACCEPT":
            self.kind = Event.EV_ACCEPT
            self.fd = int(args[0])
            self.listen_fd = int(args[1])
        elif kind == "CLOSE":
            self.kind = Event.EV_CLOSE
            self.fd = int(args[0])
        else:
            if kind == "READ":
                self.kind = Event.EV_READ
            elif kind == "WRITE":
                self.kind = Event.EV_WRITE
            else:
                raise ValueError("unknown event type: %s" % kind)
            self.syscall = int(args[0])
            self.fd = int(args[1])
            self.size = int(args[2])
            self.last_op = None

    def __str__(self):
        return "{}".format(self.kind_str()[0])

    def __repr__(self):
        return "{}".format(self.kind_str()[0])


class Log(object):
    CONN      = 1
    BROADCAST = 2
    NOTIFY    = 4
    NCONN     = BROADCAST | NOTIFY

    def __init__(self, path):
        self._log = open(path, "r")

    def __del__(self):
        if not self._log.closed:
            self._log.close()

    def process(self):
        lifetimes = dict()
        groups = dict()

        behaviour = Log.NCONN
        last = None
        last_op = None

        # Phase 1: build chunked events that we understand
        #     - socket => new socket (with timestamp)
        #     - accept => new socket (with timestamp)
        for ev in map(Event, iter(self._log)):
            if ev.kind == Event.EV_ACCEPT:
                last_op = ev
                # TODO: what happens if we get NCONN related
                #       hits prior to the accept?
                behaviour = Log.CONN

            if ev.kind == Event.EV_SOCKET or ev.kind == Event.EV_ACCEPT:
                last_op = ev
                v = [ev, None]
                lifetimes[ev.fd] = v
                g = groups.get(ev.fd, None)
                if g is None:
                    groups[ev.fd] = [v]
                else:
                    groups[ev.fd].append(v)
            elif ev.kind == Event.EV_CLOSE:
                last_op = ev
                # TODO: handle multiple closes without previously witnessing opens
                #       this will cause inconsistency!!
                v = lifetimes.get(ev.fd, None)
                if v is None: continue
                v[1] = ev
            elif ev.kind == Event.EV_READ or ev.kind == Event.EV_WRITE:
                # HEURISTIC: skip stdio
                if ev.fd in (0, 1, 2):
                    last_op = ev
                    continue

                ev.last_op = last_op
                last_op = ev

                # Handle connection-less
                if behaviour & Log.NCONN != 0:
                    gs = groups.get(ev.fd, None)
                    if gs is None:
                        v = [None, None, ev]
                        lifetimes[ev.fd] = v
                        groups[ev.fd] = [v]
                    else:
                        g = next(filter(lambda g: g[1] is None, gs), None)
                        if g is None and len(gs) > 0:
                            g = gs[-1]
                        if g is not None:
                            g.append(ev)
                    last_op = ev

                # Handle connection-based
                elif behaviour & Log.CONN != 0:
                    # HEURISTIC: skip sockets that didn't get opened within this session
                    gs = groups.get(ev.fd, None)
                    if gs is None: continue
                    g = next(filter(lambda g: g[1] is None, gs), None)
                    if g is None: continue
                    g.append(ev)

        # Phase 2: filter based on heurisitcs

        if behaviour & Log.CONN != 0:
            # For now, we work on the basis of a set of events that must contain
            # at least one read/write and the first interaction with the socket is
            # a read
            #
            # NOTE: this is indeed fragile, for example, FTP, which sends a welcome
            #       banner.
            viable = { fd: [gs for gs in gss
                            if len(gs) > 2 and (gs[0] and gs[0].kind == Event.EV_ACCEPT) and (gs[2] and gs[2].kind == Event.EV_READ)]
                       for (fd, gss) in groups.items() }
        else:
            viable = dict()
            for (fd, gss) in groups.items():
                # classify type
                kind = None
                if len(gss) == 0 or any(len(gs) <= 2 for gs in gss):
                    continue
                if gss[0][2].kind == Event.EV_READ:
                    # NOTIFY
                    skip = False
                    renc = []
                    for g in (g for gs in gss for g in gs[2:]):
                        if g.kind == Event.EV_WRITE:
                            skip = True
                            break
                        if g.kind == Event.EV_READ:
                            if g.size < 0:
                                skip = True
                                break
                            # HEURISTIC: if reads are contiguous, then they MUST all have the same size.
                            # This is because we assume that the read behaviour should be stateless, unless
                            # influenced by some other input/output behaviour
                            if g.last_op is not None and \
                               g.last_op.kind == g.kind and \
                               g.last_op.fd == g.fd and \
                               g.last_op.syscall == g.syscall and \
                               g.last_op.size != g.size:
                                skip = True
                                break
                            #if len(renc) > 0:
                            #    # NOTE: the check might work without this
                            #    #       as this is stronger, hence introduces
                            #    #       more fragility
                            #    if renc[-1].size == g.size:
                            #        renc.append(g)
                            #    elif len(renc) > 1:
                            #        renc.append(g)
                            #    else:
                            #        # no M/M chain of same size
                            #        skip = True
                            #        break
                            #else:
                            #    renc.append(g)
                    if skip: continue
                    viable[fd] = [[g for g in gs if g is None or g.kind != Event.EV_WRITE] for gs in gss]
                elif gss[0][2].kind == Event.EV_WRITE:
                    # BROADCAST
                    last = None
                    skip = False
                    matched = False
                    for g in (g for gs in gss for g in gs):
                        if g is None or g.kind not in (Event.EV_READ, Event.EV_WRITE):
                            matched = False
                            last = None
                            continue
                        if g.size <= 0:
                            skip = True
                            break
                        if last is None:
                            last = g
                            matched = False
                            continue
                        if last.kind == Event.EV_WRITE:
                            if g.kind == Event.EV_WRITE:
                                skip = True
                                break
                            elif g.kind == Event.EV_READ:
                                matched = True
                        elif last.kind == Event.EV_READ and g.kind == Event.EV_WRITE:
                            matched = False
                        last = g
                    if skip: continue
                    viable[fd] = [[g for g in gs if g is None or g.kind != Event.EV_READ] for gs in gss]
                else:
                    continue
        return viable

if __name__ == "__main__":
    cli=argparse.ArgumentParser()
    cli.add_argument("--log", help="input/output log file", required=True)
    args = cli.parse_args()

    out = []
    for (fd, gss) in Log(args.log).process().items():
        if len(gss) == 0: continue
        syscalls = set((g.syscall, g.kind_str()) for gs in gss for g in gs[2:])
        if gss[-1][-1].kind == Event.EV_READ and gss[-1][1].kind == Event.EV_CLOSE:
            # __NR_close
            syscalls.add((3, gss[-1][1].kind_str()))
        if len(syscalls) > 0:
            out.append({"fd": fd, "syscalls": list(syscalls)})
    json.dump(out, sys.stdout)
