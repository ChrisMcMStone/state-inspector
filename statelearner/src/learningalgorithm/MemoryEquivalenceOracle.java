package learningalgorithm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.google.common.base.Optional;

import org.codehaus.plexus.util.StringUtils;
import org.javatuples.Pair;

import datastructures.AllocOffset;
import datastructures.ConditionalStateMem;
import datastructures.FastMealyMemModel;
import datastructures.FastMealyMemState;
import datastructures.StateAddrSet;
import datastructures.TaintBranchAnalysis;
import datastructures.TaintResult;
import datastructures.WatchpointDump;
import datastructures.StateAddrSet.Confidence;
import greyboxinterface.TainterConfig;
import greyboxinterface.TainterInterface;
import greyboxinterface.TargetInterface;
import learner.Config;
import net.automatalib.words.Word;

public class MemoryEquivalenceOracle<I, O> {

    private static Logger log = Logger.getLogger(MemoryEquivalenceOracle.class.getName());
    private MealyOracle<I, O> mealyOracle;
    private Config config;
    private FastMealyMemModel<I, O> model;
    private TargetInterface target;
    private StatsOracle stats;
    private CoreLearner<I, O> coreLearner;

    public MemoryEquivalenceOracle(Config config, StatsOracle stats, MealyOracle<I, O> mealyOracle,
            TargetInterface target, FastMealyMemModel<I, O> model, CoreLearner<I, O> learner) {
        this.mealyOracle = mealyOracle;
        this.config = config;
        this.model = model;
        this.target = target;
        this.stats = stats;
        this.coreLearner = learner;
    }

    // ***Assume that this function is called with a list of queries FROM ONE STATE***
    // TODO should probably enforce this
    public List<TainterConfig> performTaintAnalysis(AllocOffset dAddr, byte[] expValue,
            ArrayList<Word<I>> watchpointQueries, boolean conditionalSelfWrites) throws Exception {

        TainterInterface ti = new TainterInterface(config);
        ArrayList<TainterConfig> wps = new ArrayList<>();
        HashSet<Long> stateWatchpointHitPCS = new HashSet<>();

        // Extract list of base addr, offset pairs of assumed state memory for taint
        // testing

        Set<AllocOffset> assumedMem = model.getAddrSet().getMonitorSet();

        HashSet<Integer> doneWatchStates = new HashSet<>();
        for (Word<I> input : watchpointQueries) {

            Word<I> prefix = input.prefix(-1);

            //This is required to get the minimum dump id parameter for the taint configuration 
            QueryResponseMeta qr = this.model.getMetaAtStateWithInput(prefix);

            // If there's no record of the metadata for input "prefix", try the query again
            // TODO debug why this can very rarely occur
            if(qr == null) {
                coreLearner.answerQueryUpdateModel(prefix, null, true);
                qr = this.model.getMetaAtStateWithInput(prefix);
                if(qr == null) {
                    // Give up
                    log.severe("Connot obtain correct watchpoint dumpID filter for input, ignoring.");
                    continue;
                }
            }

            TainterConfig tc = new TainterConfig(dAddr.allocBaseAddress, dAddr.allocSize, dAddr.locOffset,
                    dAddr.locSize, model.getReprLogFilename(), input.toString(), qr.getCount(), -1);

            FastMealyMemState<O> targetState = this.model.getState(input);

            //If this query is already in the model, we can filter
            if(targetState != null && (targetState.equals(this.model.getDisableState())
                                    || doneWatchStates.contains(targetState.getSID())))
                continue;

            // Run the watchpoint query and update the model in the process
            // If it fails, probably for good reason so continue to next query
            if(!coreLearner.answerQueryUpdateModel(input, tc, true)) continue;
            stats.watchpointCounter++;

            // Again check if we filter out this query in case it wasn't in the model before
            targetState = this.model.getState(input);
            if(targetState != null && (targetState.equals(this.model.getDisableState())
                                    || doneWatchStates.contains(targetState.getSID())))
                continue;
            tc.processHitLogs(this.config.outputDir);
            // **** Exclude repeated hits at the same PC and state for taint testing
            // This currently allows for repeated hits within a single query (just not for
            // repeated hits across queries)
            tc.removeHits(stateWatchpointHitPCS);

            if (this.config.a2l)
                ti.runAddr2lineHit(tc);

            if (!tc.getWpHits().isEmpty()) {
                tc.getWpHits().forEach(hit -> stateWatchpointHitPCS.add(hit.getValue1().getPc()));
                wps.add(tc);
            }

            //TODO only test one input from set that results in no state
            if(targetState != null)
                doneWatchStates.add(targetState.getSID());
        }

        // Check if we had any hits, if not return null
        if (wps.isEmpty()) {
            log.info("No watchpoint hits at tested address, assuming not state memory.");
            return null;
        }

        if (!this.config.enableTainting) {
            mealyOracle.cleanup();
            return null;
        }

        // Run the tainter for each watchpoint
        String reprLogPath = config.outputDir + "/" + model.getReprLogFilename();
        try {
            ti.runTainter(wps, assumedMem, reprLogPath, expValue, conditionalSelfWrites);
        } catch (Exception e) {
            // TODO nicen hack below to update counter incase of tainter failure
            for (TainterConfig tc : wps) {
                stats.negativeTaintCounter += tc.getWpHits().size();
            }
            throw e;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("**Taint results**\n");
        sb.append(
                "  [Base Addr,  Offset]          Addr        State Memory?   Stateful Branch?   Hit Addr(s)     Query (hits processing final input)");
        for (TainterConfig tc : wps) {
            for (TaintResult tr : tc.getWatchpointResults()) {
                sb.append("\n" + StringUtils.center("[" + Long.toHexString(dAddr.allocBaseAddress) + ",  "
                        + Long.toHexString(dAddr.locOffset) + "]", 23));
                sb.append(StringUtils
                        .center("0x" + String.valueOf(Long.toHexString(dAddr.allocBaseAddress + dAddr.locOffset)), 17));
                sb.append(StringUtils.center(tr.isStateMemory().toString(), 18));
                if (tr.isStateMemory()) {
                    stats.postiveTaintCounter++;
                    if(isStatefulTakenBranch(tr))
                        sb.append(StringUtils.center("Taken", 18));
                    else
                        sb.append(StringUtils.center("Not-taken", 18));
                } else {
                    stats.negativeTaintCounter++;
                    sb.append(StringUtils.center("N/A", 18));
                }
                sb.append(StringUtils.center("0x" + Long.toHexString(tr.getPc()), 16));
                sb.append("       " + tc.input);
            }
        }
        log.info(sb.toString());

        if (this.config.a2l)
            ti.runAddr2lineResults(wps);

        mealyOracle.cleanup();

        return wps;
    }

    private boolean isStatefulTakenBranch(TaintResult tr) {
        return tr.getExtendedResult().get().getBranchTaken().orNull() != null;
    }
    private boolean isStatefulNotTakenBranch(TaintResult tr) {
        return tr.getExtendedResult().get().getBranchNotTaken().orNull() != null;
    }

    public FastMealyMemState<O> getEqualState(HashMap<AllocOffset, Optional<byte[]>> memoryMap, Word<I> input,
            boolean happyFlow) {

        for (FastMealyMemState<O> testState : model.getMemoryDefinedStates()) {
            if (testState.equals(model.getDisableState()))
                continue;
            // Get differing addrs
            ArrayList<AllocOffset> diffs = memDiff(model.getMemMapAtState(testState), memoryMap);

            // We found an equivalent state
            if (diffs.size() == 0)
                return testState;

            // Ignore any states that differ by CONFIRMED_CONDITIONAL addrs, with the
            // conditions met
            List<AllocOffset> confCondDiffs = diffs.stream()
                    .filter(d -> this.model.getConfidence(d).equals(StateAddrSet.Confidence.CONDITIONAL))
                    .collect(Collectors.toList());

            if (confCondDiffs.size() < diffs.size())
                continue; // there is at least one addr which distinguishes the state

            if (!confCondDiffs.isEmpty()) {
                boolean isEqualState = false;
                for (AllocOffset a : confCondDiffs) {
                    ConditionalStateMem cs = areConditionalStateMemConditionsMet(a, memoryMap);
                    if (cs.isConditionsMet()) {
                        if (cs.isStateMemory()) {
                            continue;
                        } else {
                            isEqualState = true;
                        }
                    } else {
                        // Conditions for state memory have not been met, so testState is different
                        isEqualState = false;
                        break;
                    }
                }
                if (isEqualState)
                    return testState;
            }
        }
        return null;
    }

    public ConditionalStateMem areConditionalStateMemConditionsMet(AllocOffset addr,
            HashMap<AllocOffset, Optional<byte[]>> memory) {
        assert (this.model.getConfidence(addr).equals(Confidence.CONDITIONAL));
        if (StateAddrSet.dependencyMapConditionsMet(this.model.getConfirmedConditionAddrSet(addr), memory)) {
            return new ConditionalStateMem(true, true);
        } else if (StateAddrSet.dependencyMapConditionsMet(this.model.getNegativeConditionAddrSet(addr), memory)) {
            return new ConditionalStateMem(true, false);
        } else {
            return new ConditionalStateMem(false, false);
        }
    }

    public HashMap<FastMealyMemState<O>, ArrayList<AllocOffset>> nWayMemDiff(FastMealyMemState<O> baseState,
            List<FastMealyMemState<O>> list) {
        assert (list.size() > 1);
        HashMap<FastMealyMemState<O>, ArrayList<AllocOffset>> diffs = new HashMap<>();
        for (FastMealyMemState<O> currState : list) {
            if (currState.equals(baseState))
                continue;
            log.fine("Performing memory diff of states: " + baseState.getId() + " vs " + currState.getId());
            diffs.put(currState,
                    memDiff(this.model.getMemMapAtState(baseState), this.model.getMemMapAtState(currState)));
        }
        return diffs;
    }

    public ArrayList<AllocOffset> memDiff(HashMap<AllocOffset, Optional<byte[]>> base,
            HashMap<AllocOffset, Optional<byte[]>> other) {

        ArrayList<AllocOffset> sortedKeys = new ArrayList<>(base.keySet());
        Collections.sort(sortedKeys);

        ArrayList<AllocOffset> diffs = new ArrayList<>();
        for (AllocOffset key : sortedKeys) {
            if (!base.get(key).isPresent() || !other.get(key).isPresent())
                continue; // TODO for now we ignore any memory which isn't allocated in both states
            // if(!base.get(key).isPresent() && other.get(key).isPresent()) diffs.add(key);
            if (!Arrays.equals(base.get(key).orNull(), other.get(key).orNull()))
                diffs.add(key);
        }
        return diffs;
    }

    public boolean mergeTaintState(FastMealyMemState<O> base, FastMealyMemState<O> stateToMerge,
            ArrayList<AllocOffset> stateDiffs) throws Exception {
        // Initiate map of watchpoint queries, mapping (state, addr) keys -> Array of
        // (queries, dumpID number filter)
        HashMap<Pair<FastMealyMemState<O>, AllocOffset>, ArrayList<Word<I>>> watchpointQueries = new HashMap<>();
        StringBuilder sb = new StringBuilder();
        sb.append("**State Diffs**\n");
        sb.append("  [Base Addr,   Offset]          Addr           State ID");

        // Build list of watchpoint queries for each differing addresss dAddr
        for (AllocOffset dAddr : stateDiffs) {
            sb.append("\n" + StringUtils.center(
                    "[0x" + Long.toHexString(dAddr.allocBaseAddress) + ",  " + Long.toHexString(dAddr.locOffset) + "]",
                    23));
            sb.append(StringUtils.center("0x" + Long.toHexString(dAddr.allocBaseAddress + dAddr.locOffset), 17));
            sb.append(StringUtils.center(String.valueOf(stateToMerge.getId()), 17));

            // If any differing addresses are confirmed state memory, don't merge
            if (this.model.getConfidence(dAddr).equals(Confidence.CONFIRMED)) {
                log.info("State differs by address, offset [" + Long.toHexString(dAddr.allocBaseAddress) + ", "
                        + Long.toHexString(dAddr.locOffset) + "]"
                        + " which has previously been confirmed as state memory, not merging");
                return false;
            }

            // Check if differing addr is CONFIRMED but conditional on other memory values
            // if conditions NOT met, allow taint analysis on this address
            // if conditions ARE met, treat same as Confidence.CONFIRMED and return false
            if (this.model.getConfidence(dAddr).equals(Confidence.CONDITIONAL)) {
                ConditionalStateMem cs = areConditionalStateMemConditionsMet(dAddr,
                        this.model.getMemMapAtState(stateToMerge));
                if (cs.isConditionsMet()) {
                    if (cs.isStateMemory()) {
                        log.info("State differs by address, offset [" + Long.toHexString(dAddr.allocBaseAddress) + ", "
                                + Long.toHexString(dAddr.locOffset) + "]"
                                + " which has previously been confirmed as CONDITIONAL state memory, not merging");
                        return false;
                    } else {
                        // this memory does not differentiate the state, so proceed to the next
                        // differing addr
                        continue;
                    }
                }
            }

            // Change confidence state memory confidence to low for future taint test
            // triggers
            // If already confirmed, the addr confidence will not be modified
            model.updateAddrSetConfidences(dAddr, StateAddrSet.Confidence.LOW);

            if (!config.enableTainting && !config.a2l)
                continue; // don't generate watchpoint queries

            //Get any query that previously took us to the stateToMerge
            QueryResponseMeta meta = model.getMetaAtStateViaBase(stateToMerge, base);
            for (I i : this.model.getInputAlphabet()) {
                // Only test one input from each group of inputs which take us to the same state
                    Word<String> q = Word.fromArray(meta.getInputs(), 0, meta.getInputs().length).append(i.toString());
                    watchpointQueries.computeIfAbsent(new Pair<>(stateToMerge, dAddr), k -> new ArrayList<>())
                            .add((Word<I>) q);
            }
        }

        log.info(sb.toString()); // log the diffs before executing the watchpoint queries

        if (config.enableTainting && watchpointQueries != null && watchpointQueries.size() > 0) {
            if (config.enableTainting)
                log.info("Performing taint analysis on differing memory in I/O equivalent states");
            for (Pair<FastMealyMemState<O>, AllocOffset> watchKey : watchpointQueries.keySet()) {
                FastMealyMemState<O> watchState = watchKey.getValue0();
                AllocOffset watchAddr = watchKey.getValue1();
                if (config.a2l)
                    log.info("Gathering source code details of " + watchAddr.toString() + " watchpoint hits at state "
                            + watchState.getId());
                if (config.enableTainting)
                    log.info("Taint testing addr " + watchAddr.toString() + " at state " + watchState.getId());
                byte[] expVal = this.model.getMemMapAtState(stateToMerge).get(watchAddr).orNull();
                if (expVal == null)
                    continue;
                List<TainterConfig> taintResults = null;
                try {
                    taintResults = this.performTaintAnalysis(watchAddr, expVal, watchpointQueries.get(watchKey), false);
                } catch (Exception e) {
                    log.severe("Taint analysis failed, assuming tested memory is **NOT** state memory");
                    continue;
                }

                if (!config.enableTainting || taintResults == null)
                    continue;
                boolean isStateMemory = taintResults.parallelStream()
                        .anyMatch(tc -> tc.getWatchpointResults().stream().anyMatch(tr -> tr.isStateMemory()));
                if (isStateMemory) {
                    // Perform the extra taint test if configured
                    if(config.extraTaintCheck && !checkConditionalWrittenMemIsStateMem(taintResults, stateToMerge)) {
                        // TODO double check the base and toMerge state are still I/O equivalent after performing all the extra watchpoint queries
                        continue;
                    }
                    //Get stateToMerge prefix from watchpoint queries
                    coreLearner.addMergeCandidate(new Pair<>(base.getSID(), stateToMerge.getSID()));

                    boolean isNonTaken = taintResults.stream()
                            .map(tc -> tc.getWatchpointResults().stream()
                            .filter(tr -> tr.isStateMemory())
                            .allMatch(tr -> isStatefulNotTakenBranch(tr)))
                            .reduce(Boolean::logicalAnd).orElse(false);

                    // HashSet<Word<I>> permittedInputs = new HashSet<>();

                    // taintResults.stream().filter(tc -> tc.getWatchpointResults().stream()
                    //                      .anyMatch(tr -> tr.isStateMemory()))
                    //                      .forEach(tc -> permittedInputs.add((Word<I>)Word.fromList(tc.getInputList())));

                    // Here we set the confidence of this address being state to CONFIRMED,
                    // on the condition that all other non-LOW confidence addresses hold the same
                    // value at the time of testing.
                    model.updateAddrSetConfidences(watchAddr, Confidence.CONDITIONAL,
                            model.getMemMapAtState(watchState), true);
                    log.info("Taint analysis determined memory is likely state memory at address "
                            + watchAddr.toString());
                    log.info("Not merging states " + base.getSID() + " and " + stateToMerge.getSID());
                    return false;
                } else {
                    if (config.negativeConditionalMemory) {
                        model.updateAddrSetConfidences(watchAddr, Confidence.CONDITIONAL,
                                model.getMemMapAtState(watchState), false);
                    }
                }
            }
        }

        if (!config.enableTainting) {
            log.info("Taint analysis disabled so automatically merging states " + base.getSID() + " and "
                    + stateToMerge.getSID());
        } else {
            log.info("Taint analysis determined all differing memory is *NOT* influential to state, merging states "
                    + base.getSID() + " and " + stateToMerge.getSID());
        }
        this.model.mergeState(base, stateToMerge);
        return true;
    }

    private boolean checkConditionalWrittenMemIsStateMem(List<TainterConfig> toCheck, FastMealyMemState<O> stateToMerge) throws Exception {

        for (TainterConfig tc : toCheck) {
            for (TaintResult tr : tc.getWatchpointResults()) {
                if (tr.isStateMemory()) {
                    boolean isNotTaken = false;
                    TaintBranchAnalysis condWriteBranch = tr.getExtendedResult().get().getBranchTaken().orNull();
                    if (condWriteBranch == null) {
                        condWriteBranch = tr.getExtendedResult().get().getBranchNotTaken().orNull();
                        isNotTaken = true;
                    }
                    Long condWriteRawAddr = condWriteBranch.getStoreAddress().longValue();
                    AllocOffset condWriteAO = this.model.getAddrSet().getMonitorSet().stream()
                            .filter(ao -> (ao.allocBaseAddress + ao.locOffset) == condWriteRawAddr).findFirst()
                            .orElse(null);
                    if (condWriteAO == null) {
                        log.severe("Failed to map store address from taint result to rep log, ignoring this result.");
                        continue;
                    }
                    log.info("Verifying conditionally written memory " + condWriteAO.toString() + " is itself state defining");
                    // At this point we can generate watchpoint queries for condwritea0

                    ArrayList<Word<I>> watchpointQueries = new ArrayList<>();
                    Word<I> prefix = (Word<I>) Word.fromList(tc.getInputList());
                    FastMealyMemState<O> testState = null;
                    for (I i : this.model.getInputAlphabet()) {
                        // Only test one input from each group of inputs which take us to the same state
                        Word<I> q = prefix.append(i);
                        testState = model.getState(prefix);
                        watchpointQueries.add((Word<I>) q);
                    }

                    byte[] expVal = this.model.getMemMapAtState(testState).get(condWriteAO).orNull();
                    if (expVal == null)
                        continue;
                    List<TainterConfig> confirmedTaintResults = null;
                    try {
                        confirmedTaintResults = this.performTaintAnalysis(condWriteAO, expVal, watchpointQueries, true);
                    } catch (Exception e) {
                        e.printStackTrace();
                        log.severe("Taint analysis failed, assuming tested memory is **NOT** state memory");
                        continue;
                    }
                    if (!config.enableTainting || confirmedTaintResults == null)
                        continue;
                    boolean isStateMemory = confirmedTaintResults.stream().anyMatch(taintcfg -> taintcfg
                            .getWatchpointResults().stream().anyMatch(taintresult -> taintresult.isStateMemory()));
                    return isStateMemory;
                }
            }
        }
        return false;
    }
}
