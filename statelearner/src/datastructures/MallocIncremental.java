package datastructures;

import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;

import org.javatuples.Pair;
import org.javatuples.Triplet;

import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class MallocIncremental {

    private static Logger log = Logger.getLogger(MallocIncremental.class.getName());

    private ArrayList<MallocEntry> mallocs;
    private ArrayList<MallocEntry> representativeLog;
    private String representativeLogFilename;
    private int representativeLogSessionID;


    @SuppressWarnings("unchecked")
    public MallocIncremental(ArrayList<Triplet<ArrayList<MallocEntry>, Integer, String>> ls) throws Exception {

        log.fine("Building MallocIncremental with " + ls.size() + " lists");

        assert (ls.size() > 0);
        if (ls.size() == 1) {
            this.representativeLog = ls.get(0).getValue0();
            this.representativeLogFilename = ls.get(0).getValue2();
            this.representativeLogSessionID = ls.get(0).getValue1();
            this.mallocs = ls.get(0).getValue0().stream()
                    .map(m -> new MallocEntry(m.timestamp, m.size, m.pc, m.addr))
                    .collect(Collectors.toCollection(ArrayList::new));
        } else {
            int maxIndex = -1, maxLength = -1;
            for (int i = 0; i < ls.size(); i++) {
                if (ls.get(i).getValue0().size() > maxLength) {
                    maxIndex = i;
                    maxLength = ls.get(i).getValue0().size();
                }
            }
            this.representativeLogFilename = ls.get(maxIndex).getValue2();
            this.representativeLogSessionID = ls.get(maxIndex).getValue1();
            ArrayList<ArrayList<MallocEntry>> logs = new ArrayList<>();
            for (Triplet<ArrayList<MallocEntry>, Integer, String> log : ls) {
                logs.add((ArrayList<MallocEntry>)log.getValue0().clone());
            }

            this.representativeLog = logs.get(maxIndex);
            this.mallocs = new ArrayList<>();

            for (MallocEntry m : this.representativeLog) {
                ArrayList<Pair<Integer, Integer>> done = new ArrayList<>();
                for (int i = 0; i < logs.get(maxIndex).size(); i++) {
                    logLoop: for (int j = 0; j < logs.size(); j++) {
                        if (i >= logs.get(j).size()) continue;
                        if (j == maxIndex) continue;
                        for (Pair<Integer, Integer> v : done) {
                            if (v.getValue0() == j) continue logLoop;
                        }
                        if (logs.get(j).get(i).pc.equals(m.pc) && logs.get(j).get(i).size.equals(m.size)) {
                            done.add(new Pair<Integer, Integer>(j, i));
                        }
                    }
                }
                    if (done.size() == logs.size() - 1) {
                        this.mallocs.add(new MallocEntry(m.timestamp, m.size, m.pc, m.addr));
                    }
                for (Pair<Integer, Integer> e : done) {
                    logs.get(e.getValue0()).remove(e.getValue1());
                }
            }
        }
        if (this.mallocs.size() < 1) {
            log.severe("Failed to map malloc logs.");
            throw new Exception("Failed to map malloc logs.");
        }

        log.fine("Mapped a total of " + this.mallocs.size() + " mallocs");
    }

    public ArrayList<Pair<AllocOffset, Long>> getOffsets(ArrayList<MallocEntry> othMallocs, Long timestamp, Long heapBase, Multimap<Pair<Long, Long>, Pair<Long, Long>> parameters) throws Exception {
        ArrayList<Pair<AllocOffset, Long>> offsets = new ArrayList<>();
        Set<Pair<Long, Long>> done = new HashSet<>();

        // align against the largest log
        if (mallocs.size() >= othMallocs.size()) {
            // default case, we align against the repr log
            // loop for mallocs to align
            Set<MallocEntry> alreadyMatched = new HashSet<>();
            for (int i = 0; i < othMallocs.size(); i++) {
                MallocEntry toMatch = othMallocs.get(i);
                for (int j = 0; j < mallocs.size(); j++) {
                    MallocEntry possibleMatch = mallocs.get(j);

                    // skip this one if we already matched an alloc
                    if (alreadyMatched.contains(possibleMatch)) continue;

                    // we have a match that didn't previously match
                    if (toMatch.pc.equals(possibleMatch.pc) && toMatch.size.equals(possibleMatch.size)) {
                        // it's a match!
                        alreadyMatched.add(possibleMatch);
                        // match timestamp is less than the snapshot timestamp
                            MallocEntry reprAlloc = possibleMatch;
                            Pair<Long, Long> baseAlloc = new Pair<>(reprAlloc.addr, reprAlloc.size);
                            if (parameters.containsKey(baseAlloc)) {
                                // update the set of base addresses matched for all parameters
                                if (done.contains(baseAlloc)) break;
                                done.add(baseAlloc);

                                for (Pair<Long, Long> param : parameters.get(baseAlloc)) {
                                    Long offsetInAlloc = param.getValue1();
                                    Long sizeFromOffset = param.getValue0();
                                    Long justOffset = toMatch.addr.longValue() + offsetInAlloc.longValue() - heapBase.longValue();
                                    offsets.add(new Pair<>(new AllocOffset(reprAlloc.addr, reprAlloc.size, offsetInAlloc, sizeFromOffset), justOffset));
                                }
                            }
                        break;
                    }
                }
                // break early if we found all parameters
                if (offsets.size() == parameters.size()) break;
            }
        } else {
            // other case, we align against the other log
            // loop for mallocs to align
            Set<MallocEntry> alreadyMatched = new HashSet<>();
            for (int i = 0; i < mallocs.size(); i++) {
                MallocEntry toMatch = mallocs.get(i);
                for (int j = 0; j < othMallocs.size(); j++) {
                    MallocEntry possibleMatch = othMallocs.get(j);

                    // skip this one if we already matched an alloc
                    if (alreadyMatched.contains(possibleMatch)) continue;

                    // we have a match that didn't previously match
                    if (toMatch.pc.equals(possibleMatch.pc) && toMatch.size.equals(possibleMatch.size)) {
                        // it's a match!
                        alreadyMatched.add(possibleMatch);
                        // match timestamp is less than the snapshot timestamp
                            MallocEntry reprAlloc = toMatch;
                            Pair<Long, Long> baseAlloc = new Pair<>(reprAlloc.addr, reprAlloc.size);
                            if (parameters.containsKey(baseAlloc)) {
                                // update the set of base addresses matched for all parameters
                                if (done.contains(baseAlloc)) break;
                                done.add(baseAlloc);

                                for (Pair<Long, Long> param : parameters.get(baseAlloc)) {
                                    Long offsetInAlloc = param.getValue1();
                                    Long sizeFromOffset = param.getValue0();
                                    Long justOffset = possibleMatch.addr.longValue() + offsetInAlloc.longValue() - heapBase.longValue();
                                    offsets.add(new Pair<>(new AllocOffset(reprAlloc.addr, reprAlloc.size, offsetInAlloc, sizeFromOffset), justOffset));
                                }
                            }
                        break;
                    }
                }
                // break early if we found all parameters
                if (offsets.size() == parameters.size()) break;
            }
        }

        Set<Pair<Long, Long>> notFound = Sets.difference(parameters.keySet(), done);
        for (Pair<Long, Long> d : notFound) {
            for (Pair<Long, Long> param : parameters.get(d)) {
                // TODO: we should give the alloc size with the parameters; I
                // suspect it could be changed to: Multimap<Pair<Long, Long>,
                // Pair<Long, Long>>, where we have the first pair
                // (baseAllocAddress, baseAllocSize)
                offsets.add(new Pair<>(new AllocOffset(d.getValue0(), d.getValue1(), param.getValue1(), param.getValue0()), Long.valueOf(-1)));
            }
        }

        if (offsets.size() > parameters.size()) {
            throw new Exception("More offsets calculated than state memory addresses, this should NOT happen.");
        }
        return offsets;
    }

    public ArrayList<MallocEntry> getRepresentativeLog() {
        return this.representativeLog;
    }

    public String getRepresentativeLogFilename() {
        return representativeLogFilename;
    }

    public int getRepresentativeLogSessionID() {
        return representativeLogSessionID;
    }
}
