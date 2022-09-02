from collections import defaultdict
import copy

class Alloc(object):
    MALLOC = 0
    FREE = 1

    def __init__(self, line, alloc_file):
        self.time, kind, pc, *args = line.split(' ')
        if kind == 'M':
            self.kind = Alloc.MALLOC
            self.arg = int(args[0], 16)
            self.ret = int(args[1], 16)
        elif kind == 'F':
            self.kind = Alloc.FREE
            self.arg = int(args[0], 16)
        else:
            raise ValueError("invalid kind: must be M or F: %r" % line)
        self.pc = int(pc, 16)
        self.alloc_file = alloc_file
        self.lifetime_count = 1

    def is_malloc(self):
        return self.kind == Alloc.MALLOC

    @property
    def size(self):
        if self.kind == Alloc.MALLOC:
            return self.arg
        else:
            raise ValueError("Alloc of kind FREE does not have a size property")
        
    def __eq__(self, other): 
        if not isinstance(other, Alloc):
            return NotImplemented

        return self.kind == other.kind and self.pc == other.pc and \
            (self.size == other.size if self.kind == Alloc.MALLOC  else True)
            
    def __hash__(self):
        return hash((self.kind, self.pc, (self.size if self.kind == Alloc.MALLOC  else 0)))
        
def update_mallocs(alloc_file, prev_build, next_tstamp, malloc_log_files):
    mallocs = prev_build[0]
    prev_line_no = prev_build[1]
    lifetimes = prev_build[2]
    in_mem_log = malloc_log_files[alloc_file]
    line_count= 0
    for alloc in in_mem_log: 
        line_count += 1
        if line_count >= prev_line_no:
            if not int(alloc.split(' ')[0]) < next_tstamp:
                break
            m = Alloc(alloc, alloc_file)
            if m.is_malloc():
                v = [m, None]
                lifetimes[m.ret] = v
                mallocs.append(v)
            elif m.arg == 0:
                # skip frees to NULL
                continue
            else:
                v = lifetimes.get(m.arg, None)
                if v is None:
                    #print("free without corresponding malloc: %#x" %m.arg)
                    continue
                v[1] = m
    
    for m in mallocs:
        if m[1] is None:
            m[0].lifetime_count += 1
    return (mallocs, line_count, lifetimes)


def build_mallocs(alloc_file, max_timestamp=None, malloc_log_files=None):
    allocs = None
    if malloc_log_files is None:
        a_fd = open(alloc_file, 'r')
        allocs = a_fd.readlines()
        a_fd.close()
    elif alloc_file not in malloc_log_files:
        a_fd = open(alloc_file, 'r')
        allocs = a_fd.readlines()
        a_fd.close()
        malloc_log_files[alloc_file] = allocs
    else:
        allocs = malloc_log_files[alloc_file]
    mallocs = []
    lifetimes = dict()
    line_count = 0
    for alloc in allocs:
        line_count += 1
        if max_timestamp is None or int(alloc.split(' ')[0]) < max_timestamp:
            m = Alloc(alloc, alloc_file)
            if m.is_malloc():
                v = [m, None]
                lifetimes[m.ret] = v
                mallocs.append(v)
            elif m.arg == 0:
                # skip frees to NULL (aka double frees)
                continue
            else:
                v = lifetimes.get(m.arg, None)
                if v is None:
                    #print("free without corresponding malloc: %#x" %m.arg)
                    continue
                v[1] = m
        else: break
    
    return (mallocs, line_count, lifetimes)

def build_mapping_list(allocs):
    assert len(allocs) > 1
    #list_allocs = copy.deepcopy(allocs)
    list_allocs = []
    for i in range(len(allocs)):
        list_allocs.append(list(allocs[i]))
        
    biggest_alloc_log = []
    for a in list_allocs:
        if len(a) > len(biggest_alloc_log): biggest_alloc_log = a

    mapping = []
    # for each allocation in the biggest log
    for alloc in biggest_alloc_log:
        done = []
        # iterate over all allocations
        for i in range(len(biggest_alloc_log)):
            # iterate over each of the other logs
            for a_list in list_allocs:
                # ignore biggest log (since we're aligning against this)
                if a_list is biggest_alloc_log: continue
                # if we've exceeded the length of this log 
                if i >= len(a_list): continue
                # ignore logs we've already matched
                if any(a_list is x[0] for x in done): continue
                # if we find a PC/SIZE alloc match
                if a_list[i][0].pc == alloc[0].pc and a_list[i][0].size == alloc[0].size:
                    a_alloc = a_list[i]
                    done.append((a_list, i, a_alloc))
            if len(done) == len(list_allocs)-1:
                res = [x[2] for x in done]
                res.append(alloc)
                res.sort(key=lambda x: x[0].alloc_file)
                mapping.append(res)
                break
        for e in done: e[0].pop(e[1])
    
    return mapping
    

def build_mapping(allocs1, allocs2):
    allocs2_copy = list(reversed(allocs2))
    mapping = []
    for alloc in reversed(allocs1):
        found = False
        for i in range(len(allocs2_copy)):
            # only map open allocations (ignore those that have been freed)
            if allocs2_copy[i][0].pc == alloc[0].pc and allocs2_copy[i][0].size == alloc[0].size:
            #and (allocs2_copy[i][0].kind != Alloc.FREE and alloc[0].kind != Alloc.FREE):
                alloc2 = allocs2_copy.pop(i)
                mapping.append([alloc, alloc2])
                found = True
                break
        if not found:
            #raise ValueError("no mapping found for %r" % alloc[0])
            pass
            #print("no mapping found for %r" % alloc[0])
    return mapping

def mapping(log1, log2):

    m1 = build_mallocs(log1)[0]
    m2 = build_mallocs(log2)[0]

    if len(m1) <= len(m2):
        mapping = build_mapping(m1, m2)
    else:
        mapping = build_mapping(m2, m1)

    return mapping
