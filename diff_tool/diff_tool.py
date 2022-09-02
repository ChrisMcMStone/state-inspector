import malloc_align
import math
import logging
import argparse
import json as jsonlib
import sys
import utils

logger = logging.getLogger("diff_tool")
debug = False
json = False

def malloc_state_mem(grouped_snaps, heap_base, mapped_ranges, max_alloc_size, rep_log, terminating_outputs):
    # log_name -> ([Allocs], line_no, lifetimes)
    
    # malloc_dict[key=sessionID] = list of malloc objects(pc, size, sessID/malloglog, etc)
    malloc_log_files = {}
    malloc_dict = {}
    malloc_dict[rep_log] = malloc_align.build_mallocs(rep_log, None, malloc_log_files)
    

    # state_mem_dict[key=tuple(size, pc, offset)] = list of alloc objects (max of 1 per alloc_file/sessionID)
    state_mem_dict = {}
    state_mem_vals = {}

    # stats counters
    round = 0
    pointer_count = 0
    ra_cnt = 0
    ro_cnt = 0
    
    # elements which at some point violate state mem assumptions, so we remove at end
    to_remove_offsets = []
    to_remove_allocs = set()

    # TODO filter out re-allocation M-F pairs from logs (from the timestamp of the first snapshot)
    # this is a fundamental assumptions of state memory 
    
    # For every group of snapshots taken at equivalent I/O seqs
    for gs in grouped_snaps:
        
        round += 1
        
        val_added_round = []

        if len(gs) < 2:
            if not json: logger.error("Round has less than two %s snapshots with I/O seq: %s" % 
                                     (gs[0]["type"], str(gs[0]["inputs"]) + " / " + str(gs[0]["outputs"])))
            continue

        if not json: logger.info("Round %d: processing %d snapshots at I/O seq: %s" % (round, len(gs), str(gs[0]["inputs"]) + " / " + str(gs[0]["outputs"])))

        sessions_in_this_round = [rep_log]
        rep_log_in_round = False
        s_fhs = []
        num_ffed_rounds = 0
        
        # This iteratively builds up the mallocs to the current point in the query flow
        for s in gs:
            log_name = s["malloc_log"]
            snap_file = s["dump_file"]
            is_zeroed = True if s["zeroed"] == 1 else False
            if not is_zeroed: num_ffed_rounds+=1
            # Read snapshot into memory
            fh = open(snap_file, 'rb')
            dump = fh.read()
            fh.close()
            s_fhs.append((dump, log_name, is_zeroed))
            if log_name == rep_log: 
                rep_log_in_round = True
                continue
            if log_name not in malloc_dict:
                malloc_dict[log_name] = malloc_align.build_mallocs(log_name, 
                                                                   s["timestamp"],
                                                                   malloc_log_files)
            else:
                malloc_dict[log_name] = malloc_align.update_mallocs(log_name, 
                                                                    malloc_dict[log_name], 
                                                                    s["timestamp"],
                                                                    malloc_log_files)
            sessions_in_this_round.append(log_name)

        num_sessions_in_this_round = len(sessions_in_this_round) if rep_log_in_round else len(sessions_in_this_round)-1
        
        if debug:
            bm_size_str = ""
            for k in malloc_dict:
                bm_size_str += str(len(malloc_dict[k][0])) + " "
            logger.debug("Round %d - built mallocs, size: %s" % (round,bm_size_str))

        # map allocations in each malloc_dict element for this round (i.e. consisting of (lists of len(gs) )
        mallocs = [malloc_dict[k][0] for k in sessions_in_this_round]
        mappings = malloc_align.build_mapping_list(mallocs)
        
        # Uncomment below to print the aligned malloc entries in debug mode
        # if debug:
        #     for m in mappings:
        #         for n in m:
        #             print(str(hex(n[0].ret)) + "," + str(hex(n[0].size)) + "  ", end="")
        #         print("")

        if len(mappings) < 1:
            if not json: logger.info("No mallocs aligned in this round")
            continue
        
        logger.debug("Round %d - built mapping list, size: %d" % (round, len(mappings)))
        
        for maps in mappings:
            
            # SOME SANITY CHECKS FIRST
            ##########################
            # 1. verify maps = [len(gs) of allocs]
            if len(maps) != len(sessions_in_this_round):
                logger.error("Mapped an allocation in more or less logs than being processed by this round. This should not happen so exiting...")
                exit(-1)
            
            # Get the according allocation from the rep log
            rep_alloc = next(m[0] for m in maps if m[0].alloc_file == rep_log)
                
            num_freed = 0
            # check allocs in maps are not freed
            # if some freed and others not, this is defintely not state memory so mark for removal
            # (ignore the rep_log alloc as that is not timestamp limited)
            for m in [n for n in maps if n[0] is not rep_alloc]:
                if m[1] is not None:
                    num_freed += 1
                    
            if num_freed > 0:
                # All bets are off after a terminating output
                isTO = False
                if len(gs[0]['outputs']) > 0:
                    for to in terminating_outputs:
                        if to in gs[0]['outputs'][-1]:
                            isTO = True
                
                # if not terminating output, and allocs are inconsistently active, remove
                if not isTO and num_freed != (len(maps)-1):
                    to_remove_allocs.add(rep_alloc)
                    
                continue
            #########################
            
            
            alloc_size = rep_alloc.size
            alloc_pc = rep_alloc.pc
            alloc_ret = rep_alloc.ret
            
            # filter out allocs exceeding max size
            if alloc_size > max_alloc_size:
                continue
            
            for offset in range(alloc_size):
                # init the key for the state memory entry
                sm = (alloc_size, alloc_pc, offset, alloc_ret)
            
                # This contains all the values a given mapping:offset pair takes in all snapshots of the group
                vals = []
                
                # Determine whether we have detected a piece of state memory `sm` in a previous round
                is_prev_round_statemem = sm in state_mem_dict
                
                for (s, slog, is_zeroed) in s_fhs:
                    # get alloc object from snapshots map
                    s_alloc = next((x for x in maps if x[0].alloc_file == slog), None)[0]
                    
                    # dont read the rep_log value if it's not in this round
                    #if not rep_log_in_round: continue
                    
                    # calculate the read address
                    read_addr = (s_alloc.ret + offset) - heap_base
                    
                    try:
                        # read the byte
                        val = s[read_addr]
                    except:
                        continue
                    
                    change_val = 0x00 if is_zeroed else 0xff
                   
                    # only if value has changed or the `sm` has been previously logged as state memory
                    if val != change_val or is_prev_round_statemem:
                        # check it wasn't initialised as pointer
                        p_start_range = read_addr - utils.POINTER_SIZE
                        p_end_range = p_start_range + (utils.POINTER_SIZE*2)
                        fhv = s[p_start_range:p_end_range]
                        if not utils.is_pointer([fhv], mapped_ranges):
                            vals.append(val)
                        else:
                            to_remove_offsets.append(sm)
                            pointer_count += 1
                
                if len(vals) != 0:
                    # Ensure that the value is:
                    # a) the same in all snapshots
                    # b)i) if it is zero, ensure that we read n values, where n = #snapshots in this round with FFed memory init
                    # b)ii) if it is non-zero, ensure that we read n values, where n = #snapshots in this round with zeroed memory init
                    if len(set(vals)) == 1 and \
                        ( (vals[0] == 0x00 and len(vals) >= math.ceil(num_ffed_rounds*0.9)) or \
                          (vals[0] != 0x00 and len(vals) >= math.ceil((num_sessions_in_this_round-num_ffed_rounds)*0.9)) ):
                        # we have some candidate state memory
                        if sm in state_mem_dict:
                            if sm not in val_added_round:
                                state_mem_vals[sm].append(hex(vals[0]))
                                val_added_round.append(sm)
                                continue
                        else:
                            state_mem_dict[sm] = rep_alloc
                            
                            # Add the values to a seperate dict
                            val_added_round.append(sm)
                            if not sm in state_mem_vals:
                                state_mem_vals[sm] = [hex(vals[0])]
                            else:
                                state_mem_vals[sm].append(hex(vals[0]))

                    else:
                        # the memory should be removed at the end if it has been classified as
                        # state memory in a different round
                        to_remove_offsets.append(sm)
                        # TODO return the to_remove_offsets such that learner can drop state memory that defies assumptions after doing type inference/bound extension.
                        
    if mapped_ranges is None:
        if not json: logger.warning("No pointers removed")
    else:
        if not json: logger.info("Ignored %d candidate values detected as pointers." % (pointer_count))
        
        
    rlog_map_count = 0
    rlog_map_count_fail = 0
    
    ## Perform removal of state memory which violates assumptions at some point during handshake
    for ra in to_remove_allocs:
        rm = False
        for sm in list(state_mem_dict):
            if sm[0] == ra.size and sm[1] == ra.pc and sm[3] == ra.ret:
                rm = True
                del state_mem_dict[sm]
                del state_mem_vals[sm]
        if rm: 
            ra_cnt += 1
            logger.debug("Removed whole alloc of size %s" % str(hex(ra.size)))
    
    for ro in to_remove_offsets:
        if state_mem_dict.pop(ro, None):
            state_mem_vals.pop(ro, None)
            ro_cnt += 1
            logger.debug("Removed offset %s from alloc of size %s" % (str(hex(ro[2])), str(hex(ro[0]))))
                
    # Sanity checks
    for sm in list(state_mem_dict):
        if sm not in state_mem_vals:
            del state_mem_dict[sm]
        elif len(state_mem_vals[sm]) > len(grouped_snaps):
            del state_mem_dict[sm]
            
    logger.debug("Removed %d allocs not consistently freed across sessions" % ra_cnt)
    logger.debug("Removed %d state mem locations with non-consistent values across snapshots of same type" % ro_cnt)

    if not json: logger.info("%d pre-filtered state mem locations found" % len(state_mem_dict))
                
    return (state_mem_dict, state_mem_vals)

# returns updated state_mem_dict to remove entries via applied heuristics 
def apply_hueristics(state_mem_dict, state_mem_vals, gap_orig):
    
    # Filter out allocations which store only static data
    s_count = 0
    fil = set()
    # First locate all the allocations with changeable memory
    # excluded very small allocations
    for sm in state_mem_dict:
        nkey = (sm[0], sm[1], sm[3])
        if len(set(state_mem_vals[sm])) > 1 or sm[0] < 0x20:
            fil.add(nkey)
    # Now remove any bytes which do not fall into one of these allocations
    for sm in list(state_mem_dict):
        if (sm[0], sm[1], sm[3]) not in fil:
            del state_mem_dict[sm]
            s_count += 1
            
    if not json: logger.info("Removed %d entries part of a totally static data allocation." % s_count)

    sb_count = 0
    # Now remove static buffers
    contigous_ranges = _get_contigous_ranges(state_mem_dict, gap_orig)
    
    for cr in contigous_ranges:
        static = True
        #sm = (alloc_size, alloc_pc, offset, alloc_ret)
        for sm in state_mem_dict:
            # if the sm entry is within a contigous range
            if (sm[0], sm[1], sm[3]) == (cr[0][0], cr[0][1], cr[0][3]) and sm[2] >= cr[0][2] and sm[2] <= cr[1][2]:
                # if the values it takes are either:
                # a) always the same single value
                # b) two values, including one zero (removes big buffers which are initialy zero, but then zet to some value later on)
                pos_vals = set(state_mem_vals[sm])
                if len(pos_vals) > 1 and not (len(pos_vals) == 2 and 0x00 in pos_vals):
                    static = False
                    break
        if static:
            for sm in list(state_mem_dict):
                if (sm[0], sm[1], sm[3]) == (cr[0][0], cr[0][1], cr[0][3]) and sm[2] >= cr[0][2] and sm[2] <= cr[1][2]:
                    del state_mem_dict[sm]
                    sb_count += 1
        
    if not json: logger.info("Removed %d entries part of a contigous static state_mem buffer." % sb_count)
    
    return state_mem_dict
                    
                    
def _get_contigous_ranges(state_mem_dict, gap_orig):
    # extract contiguous alloc offsets, so we can remove static buffers
    MIN_BUFFER_SIZE = 20
    last_offset = None
    last_key = None
    
    start_range = None
    end_range = None
    
    # list of (alloc base, size, offset) tuples
    contigous_ranges = []
    for sm in state_mem_dict:
        curr_key = (sm[0], sm[1], sm[3])
        
        # check we are in the same alloc as prev iter
        if last_key is None or last_key == curr_key:
            if last_offset is None:
                start_range = sm
            elif sm[2] == last_offset + 1:
                # contigous
                end_range = sm
            else:
                jumped_gap = False
                # for g in range(1, gap_orig+1):
                #     if sm[2] == last_offset + 1 + g:
                #         jumped_gap = True
                #         end_range = sm
                if not jumped_gap:
                    # contigous ranges is of size at least 8 bytes + gap (disabled for now)
                    if end_range is not None and (end_range[2] - start_range[2] > MIN_BUFFER_SIZE): 
                        contigous_ranges.append((start_range, end_range))
                    start_range = sm
                    end_range = None
        else:
            # we have entered a new alloc 
            if end_range is not None and (end_range[2] - start_range[2] > MIN_BUFFER_SIZE): 
                contigous_ranges.append((start_range, end_range))
            start_range = sm
            end_range = None
            
        last_key = (sm[0], sm[1], sm[3])
        last_offset = sm[2]
        
    return contigous_ranges

# returns a dict mapping state_mem keys to confidence values
def calc_confidences(state_mem_dict, vals):
    
    confs = {}
    
    for sm in state_mem_dict:
        if len(vals[sm]) > 1 and len(set(vals[sm])) > 1:
            confs[sm] = "HIGH"
        else:
            confs[sm] = "LOW"
    
    return confs
    

if __name__ == "__main__":
    CLI=argparse.ArgumentParser()
    CLI.add_argument("--logs", help="List of snapshot logs, e.g. `ls snapshot_directory/*.log`", required=True, nargs='+')
    CLI.add_argument("--mem-maps", help="/proc/(PID)/maps mem-maps file (also generated by ptrace-statemem)", required=True)
    #CLI.add_argument("--min-mem-life", help="minimum number of snapshots that memory allocations must be present in", required=False, type=int, default=3)
    #CLI.add_argument("--is-zerod", help="assume mallocs zero out memory, so we can diff with only two snapshots (default false)", required=False, action="store_true", default=False)
    CLI.add_argument("--terminating-outputs", help="list of abstract strings for terminating outputs e.g. ConnClosed, Deauthentication", nargs='+', required=False, default=[])
    CLI.add_argument("--output-log", help="file path to dump diff tool human readable output", default="stateaddrset.log")
    CLI.add_argument("--print-malloc", help="print located state memory as heap malloc addresses + offsets", default=False, action="store_true")
    CLI.add_argument("--json", help="format output as JSON", default=False, action="store_true")
    CLI.add_argument("--debug", help="print debug information", default=False, action="store_true")
    CLI.add_argument("--max-alloc", help="maximum size of allocated memory (useful for filtering out large buffers storing assumed non-state data)", type=int, required=False, default=0x5000)
    CLI.add_argument("--mlog-filter", help="only ouput heap base addresses from specified malloc log (only supported in JSON output mode)", required=False)
    CLI.add_argument("--apply-hueristics", required=False, default = False, action="store_true")
    CLI.add_argument("--calc-confidences", required=False, default = False, action="store_true")
    args = CLI.parse_args()

    debug = True if args.debug else False
    json = True if args.json else False
    logging.basicConfig(format="%(asctime)s (%(levelname)s): %(message)s",
                        level=logging.DEBUG if args.debug else logging.INFO)

    logs = utils.load_logs(sorted(args.logs))
    
    # Assume the first log is the representative one for now
    rep_log = args.mlog_filter if args.mlog_filter else logs[0]['malloc_log']

    grouped_snaps = utils.group_by_io_type(logs, True, args.terminating_outputs)

    heap_base, mapped_ranges = utils.parse_mem_maps(args.mem_maps)

    (state_mem, vals) = malloc_state_mem(grouped_snaps, heap_base, mapped_ranges, args.max_alloc, rep_log, args.terminating_outputs)
    
    if args.apply_hueristics:
        state_mem = apply_hueristics(state_mem, vals, 1)
        
    confidences = None
    if args.calc_confidences:
        confidences = calc_confidences(state_mem, vals)

    if not json: logger.info("%d total state mem locations found" % len(state_mem))
    
    f = open(args.output_log, "w")
    rf = '|  {:^26} {:^10} {:^10} {:^%d} {:^10} |\n' % (len(grouped_snaps) * 6+2)
    f.write(rf.format("(Rep-log) Malloc heap addrs", "Size", "Offset", "Values", "Confidence"))
    if args.print_malloc: print(rf.format("(Rep-log) Malloc heap addrs", "Size", "Offset", "Values", "Confidence"), end="")
    for sm in sorted(state_mem):
        size = sm[0]
        offset = sm[2]
        rep_addr = sm[3]
        rf = '|  {:^26} {:^10} {:^10} {:^%d} {:^10} |\n' % (len(grouped_snaps) * 6+2)
        f.write(rf.format(str(hex(state_mem[sm].ret)), str(hex(size)), str(hex(offset)), str(vals[sm]), confidences[sm] if confidences else "N/A"))
        if args.print_malloc: print(rf.format(str(hex(state_mem[sm].ret)), str(hex(size)), str(hex(offset)), str(vals[sm]), confidences[sm] if confidences else "N/A"), end="")

            
    if json:
        t = lambda addrs, base, size, pc, offset, confidence: {"heap_addr": addrs,
                                                     "heap_base":base,
                                                     "size": size,
                                                     "pc": pc,
                                                     "offset": offset,
                                                     "confidence": confidence}
                                                                
        to_dump = []
        for sm in state_mem:
            size = sm[0]
            pc = sm[1]
            offset = sm[2]
            # Filter out addresses of memory not present in representative log
            if state_mem[sm].alloc_file == args.mlog_filter:
                to_dump.append(t(state_mem[sm].ret, heap_base, size, pc, offset, confidences[sm]))
        jsonlib.dump(to_dump, sys.stdout)
