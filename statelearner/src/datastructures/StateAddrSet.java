package datastructures;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import com.google.common.base.Optional;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.javatuples.Pair;

public class StateAddrSet {

    public enum Confidence {
        CONFIRMED, CONDITIONAL, DEFAULT, LOW
    }

    private static Logger log = Logger.getLogger(StateAddrSet.class.getName());
    // Maps heap base address + alloc size, to size + offset
    private TreeMultimap<Pair<Long, Long>, Pair<Long, Long>> monitorAddrsMap;
    private HashMap<AllocOffset, Confidence> addrConfidenceMap;
    private HashSet<AllocOffset> confirmedConditionalAddrs;
    private Multimap<AllocOffset, HashMap<AllocOffset, Optional<byte[]>>> confidenceDependencyMapConfirmed;
    private Multimap<AllocOffset, HashMap<AllocOffset, Optional<byte[]>>> confidenceDependencyMapNegative;
    private long heapBase = 0;

    public StateAddrSet() { }

    public StateAddrSet(String jsonAddrSet) throws Exception {

        TreeMultimap<Pair<Long, Long>, Pair<Long, Long>> monitorAddrsMap = TreeMultimap.create(); 
        HashMap<AllocOffset, Confidence> addrConfidenceMap = new HashMap<>();
        this.confidenceDependencyMapConfirmed = ArrayListMultimap.create();
        this.confidenceDependencyMapNegative = ArrayListMultimap.create();
        this.confirmedConditionalAddrs = new HashSet<>();

        JsonArray jsonArray = JsonParser.parseString(jsonAddrSet).getAsJsonArray();

        for (int i=0; i<jsonArray.size(); i++) {
            JsonObject ob = jsonArray.get(i).getAsJsonObject();
            Long heapAddr = ob.get("heap_addr").getAsLong();
            Long heapSize = ob.get("size").getAsLong();
            Long offset = ob.get("offset").getAsLong();
            Long size = Long.valueOf(1l);
            monitorAddrsMap.put(new Pair<Long, Long>(heapAddr, heapSize), new Pair<Long,Long>(size, offset));

            //Confidence conf = Confidence.valueOf(ob.get("confidence").getAsString().toUpperCase());
            addrConfidenceMap.put(new AllocOffset(heapAddr, heapSize, offset, size), Confidence.DEFAULT);

            //set heap base address of rep log
            if (this.heapBase == 0) this.heapBase = ob.get("heap_base").getAsLong();
        }
        this.setMonitorAddrsMap(monitorAddrsMap);
        this.setAddrConfidenceMap(addrConfidenceMap);
    }

    public long getHeapBase() {
        return heapBase;
    }

    public void setHeapBase(long heapBase) {
        this.heapBase = heapBase;
    }

    public Set<AllocOffset> getMonitorSet() {
        return this.addrConfidenceMap.keySet();
    }

    public TreeMultimap<Pair<Long, Long>, Pair<Long, Long>> getMonitorAddrsMap() {
        return monitorAddrsMap;
    }

    public void setMonitorAddrsMap(TreeMultimap<Pair<Long, Long>, Pair<Long, Long>> newSet) {
        this.monitorAddrsMap = newSet;
    }

    public HashMap<AllocOffset, Confidence> getAddrConfidenceMap() {
        return addrConfidenceMap;
    }

    public void setAddrConfidenceMap(HashMap<AllocOffset, Confidence> addrConfidenceMap) {
        this.addrConfidenceMap = addrConfidenceMap;
    }

	public boolean updateConfidence(AllocOffset addr, Confidence newConfidence) {
        if(!this.addrConfidenceMap.get(addr).equals(Confidence.CONFIRMED)) {
            this.addrConfidenceMap.replace(addr, newConfidence);
            return true;
        }
        return false;
	}

    public void updateConfidenceDependencyMapConfirmed(AllocOffset addr, HashMap<AllocOffset, Optional<byte[]>> stateMem) {
        //Only set non-LOW/CONDITIONAL confidence memory as required 
        HashMap<AllocOffset, Optional<byte[]>> dependantMemory = new HashMap<>(stateMem);
        //Don't depend on memory which is low confidence
        dependantMemory.keySet().removeIf(k -> this.addrConfidenceMap.get(k).equals(Confidence.LOW));
        // //Don't depend on memory which has only ever taint tested negative
        dependantMemory.keySet().removeIf(k -> this.addrConfidenceMap.get(k).equals(Confidence.CONDITIONAL)
                                                && !this.confirmedConditionalAddrs.contains(k));
        //Positive memory should not be conditional on itself
        dependantMemory.remove(addr);

        this.confidenceDependencyMapConfirmed.put(addr, dependantMemory);
    }

    public Collection<HashMap<AllocOffset,Optional<byte[]>>> getConfidenceDependencyMapConfirmed(AllocOffset addr) {
        return confidenceDependencyMapConfirmed.get(addr);
    }

    public void updateConfidenceDependencyMapNegative(AllocOffset addr, HashMap<AllocOffset, Optional<byte[]>> stateMem) {
        //Only set non-LOW/CONDITIONAL confidence memory as required 
        HashMap<AllocOffset, Optional<byte[]>> dependantMemory = new HashMap<>(stateMem);
        dependantMemory.keySet().removeIf(k -> this.addrConfidenceMap.get(k).equals(Confidence.LOW));
        dependantMemory.keySet().removeIf(k -> this.addrConfidenceMap.get(k).equals(Confidence.CONDITIONAL)
                                                && !this.confirmedConditionalAddrs.contains(k));

        //Negative memory should not be conditional on itself
        dependantMemory.remove(addr);

        //TODO should check whether we're adding a duplicate 
        this.confidenceDependencyMapNegative.put(addr, dependantMemory);
    }
    

    public Collection<HashMap<AllocOffset,Optional<byte[]>>> getConfidenceDependencyMapNegative(AllocOffset addr) {
        return confidenceDependencyMapNegative.get(addr);
    }

    public static boolean dependencyMapConditionsMet(Collection<HashMap<AllocOffset,Optional<byte[]>>> depMap, HashMap<AllocOffset,Optional<byte[]>> memory) {
        return depMap.stream().anyMatch(
                            c -> c.keySet().stream().allMatch(
                                a -> 
                                    (c.get(a).orNull() == null && memory.get(a).orNull() == null) ||
                                    (memory.get(a).orNull() != null && c.get(a).orNull() != null 
                                        && Arrays.equals(c.get(a).get(), memory.get(a).get()))));
    }
}
