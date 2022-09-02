package learningalgorithm;

import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.google.common.base.Optional;

import org.javatuples.Pair;
import org.javatuples.Triplet;

import bootstrapstrategies.BootstrapFlowStrategy;
import datastructures.AllocOffset;
import datastructures.FastMealyMemModel;
import datastructures.FastMealyMemState;
import datastructures.MallocEntry;
import datastructures.MallocIncremental;
import datastructures.Snapshot;
import datastructures.Snapshot.Type;
import datastructures.StateAddrSet.Confidence;
import de.learnlib.api.exception.SULException;
import datastructures.StateAddrSet;
import greyboxinterface.StateDiffInterface;
import greyboxinterface.StateMemInterface;
import greyboxinterface.TainterConfig;
import greyboxinterface.TargetInterface;
import learner.Config;
import net.automatalib.automata.transducers.impl.compact.CompactMealy;
import net.automatalib.util.automata.equivalence.NearLinearEquivalenceTest;
import net.automatalib.words.Word;
import utils.Flow;
import utils.Utils;

public class CoreLearner<I, O> {

    private static Logger log = Logger.getLogger(CoreLearner.class.getName());
    private int MAX_INCONSISTENT_RETRIES = 3;
    private int MAX_SNAPSHOT_FAIL = 3;
    private TargetInterface target;
    private StateDiffInterface diffTool;
    private FastMealyMemModel<I, O> model;
    private MealyOracle<I, O> oracle;
    private MemoryEquivalenceOracle<I, O> memOracle;
    private StateMemInterface memInterface;
    private LinkedList<Word<I>> queryQueue;
    private HashSet<Word<I>> queryBlacklist;
    private HashMap<Word<I>, Word<O>> queryDoneCache;
    //Set of state IDs <base, merge, merge state word>
    private HashSet<Pair<Integer, Integer>> mergeCandidates;
    private Config config;
    private int CTR_INCONSISTENT = 0;
    private int CTR_SNAPSHOT_FAIL = 0;
    private StatsOracle stats;

    public CoreLearner(MealyOracle<I, O> oracle, StatsOracle stats, TargetInterface target, StateDiffInterface diffTool,
            FastMealyMemModel<I, O> model, Config config) {
        this.diffTool = diffTool;
        this.model = model;
        this.oracle = oracle;
        this.stats = stats;
        this.memOracle = new MemoryEquivalenceOracle<>(config, stats, oracle, target, model, this);
        this.queryQueue = new LinkedList<>();
        this.queryDoneCache = new HashMap<>();
        this.queryBlacklist = new HashSet<>();
        this.config = config;
        this.target = target;
        this.mergeCandidates = new HashSet<>();
    }

    public void bootstrap(BootstrapFlowStrategy<I, O> bootstrapStrategy, int iterationsPerBootstrapFlow)
            throws Exception {

        // List of all the malloc details for each bootstrap flow
        // MallocEntry list, sessionID, log file name
        ArrayList<Triplet<ArrayList<MallocEntry>, Integer, String>> mEntries = new ArrayList<>();

        // Array storing results one of each boostrap query, to be used in updating the
        // model after state memory is set
        ArrayList<QueryResponse<I, O>> bootstrapQrs = new ArrayList<>();
        ArrayList<QueryResponse<I, O>> excludedBootstrapQrs = new ArrayList<>();

        ArrayList<Flow<I, O>> flows = bootstrapStrategy.generateBootstrapFlows();

        for (Flow<I, O> flow : flows) {
            boolean zeroed = false;
            for (int i = 0; i < iterationsPerBootstrapFlow; i++) {

                // If enabled, each iteration of a given bootstrap flow, we switch whether the memory is:
                // a) zeroed out upon allocation
                // b) Has 0xFF written upon allocation
                if(!config.memoryInitAlternate) {
                    zeroed = true;
                } else {
                    zeroed = !zeroed;
                }

                // If learner instrumented target launching is configured, (re)launch the target
                // and if successful, call the oracle setup
                if (this.target.launchTarget(false) && !config.signalPtraceAttach)
                    oracle.setUp();

                if (config.bootstrapMode == Config.supportedBootstrapModes.HAPPYFLOWMUTATEDSLOW
                        || config.bootstrapMode == Config.supportedBootstrapModes.HAPPYFLOWSLOW)
                    oracle.toggleSlowReset();

                Word<I> query = Word.fromList(flow.getInputs());
                QueryResponse<I, O> qrs = null;
                while (qrs == null) {
                    try {
                        qrs = oracle.answerQuery(query, zeroed);
                    } catch (EOFException e) {
                        log.severe("Snapshot read error, retrying query.");
                    } catch (SULException e) {
                        log.severe(e.getMessage());
                        log.severe("Attempting to relaunch target");
                        if (target.launchTarget(true) && !config.signalPtraceAttach)
                            oracle.setUp();
                        else
                            throw e;
                    }
                }
                stats.bootstrapCounter++;

                if (flow.isHappyFlow())
                    qrs.setHappyFlow(true);

                // Clean up the bootstrap flow
                bootstrapStrategy.flowCleanup(qrs);
                // Trim the flow for future iterations
                flow.setInputs(qrs.getInputWord());

                // filter out flows according to bootstrap strategy
                if (!bootstrapStrategy.isPermitted(qrs, flow)) {
                    excludedBootstrapQrs.add(qrs);
                    break;
                }

                if (flow.isHappyFlow()) {
                    // Malloc log will be same for every element of query, so just get first.
                    String logFile = qrs.getQrs().get(0).getMalloc_log();
                    ArrayList<MallocEntry> mEntry = null;
                    try {
                        mEntry = MallocEntry.buildMallocEntryList(Paths.get(logFile));
                    } catch (IOException e) {
                        log.severe("Failed to build MallocEntryList during bootstraps.");
                        throw e;
                    }
                    log.info("Built MallocEntry list of size: " + mEntry.size());

                    mEntries.add(new Triplet<ArrayList<MallocEntry>, Integer, String>(mEntry,
                            Integer.valueOf(oracle.getSessionID()), Paths.get(logFile).getFileName().toString()));

                    // Check outputs were as expected if specified in the config
                    if (flow.getOutputs() != null && flow.getOutputs().size() != 0) {
                        Word<O> response = qrs.getOutputWord();
                        if (!response.asList().equals(flow.getOutputs())) {
                            log.severe("Bootstrap flow failed at input " + flow.getInputs() + " Expected - "
                                    + flow.getOutputs() + " Received - " + response.toString());
                            throw new Exception("Unexpected bootstrap outputs");
                        }
                    }
                }
                bootstrapQrs.add(qrs);
            }
        }

        log.info("Using " + (bootstrapQrs.size() / iterationsPerBootstrapFlow)
                + " unique bootstrap flows, each executed " + iterationsPerBootstrapFlow + " times for diff tool");

        MallocIncremental mInc = null;
        // Build malloc mappings
        mInc = new MallocIncremental(mEntries);

        model.setReprLogFilename(mInc.getRepresentativeLogFilename());
        // We can now init mem interface
        this.memInterface = new StateMemInterface(mInc);
        log.info("Using representative log from " + mInc.getRepresentativeLogFilename() + " sessionID "
                + mInc.getRepresentativeLogSessionID());

        List<Integer> includedFlows = bootstrapQrs.stream().map(qr -> qr.getSessionID()).collect(Collectors.toList());

        // Get locations of state memory
        StateAddrSet as = diffTool.getStateMemory(mInc.getRepresentativeLogFilename(),
                mInc.getRepresentativeLogSessionID(), includedFlows);

        if (as == null || as.getMonitorAddrsMap().size() < 1) {
            log.severe("No state memory has been set");
            throw new Exception("No state memory has been set");
        }

        log.info("Using " + as.getMonitorAddrsMap().size()
                + " addresses of bytes in heap memory for state classification.");
        model.setAddrSet(as);
        stats.setMemoryStats(as);

        // Update model with bootstrap flows
        for (QueryResponse<I, O> qr : bootstrapQrs) {
            this.updateModel(qr);
        }
        for (QueryResponse<I, O> qr : excludedBootstrapQrs) {
            this.updateModel(qr);
        }

        ArrayList<Word<I>> newQueries = new ArrayList<>();
        // Queue initial state queries
        for (I suffix : model.getInputAlphabet()) {
            newQueries.add(Word.fromLetter(suffix));
        }
        queueQueryList(newQueries, this.queryQueue);
    }

    // This will update the model with the information learnt from a given query.
    // If a new state is discovered, we also queue new queries to the learner.
    private boolean updateModel(QueryResponse<I, O> qr) throws Exception {

        //if (model.getSuccessor(model.getInitialState(), qr.getInputWord()) != null)
        //    return true;

        FastMealyMemState<O> curr = model.getInitialState();
        for (int j = 0; j < qr.getOutputWord().size(); j++) {
            I i = qr.getInputWord().getSymbol(j);
            O o = qr.getOutputWord().getSymbol(j);

            Word<I> iPrefix = j < (qr.getInputWord().size() - 1) ? qr.getInputWord().prefix(j + 1) : qr.getInputWord();
            Word<O> oPrefix = j < (qr.getInputWord().size() - 1) ? qr.getOutputWord().prefix(j + 1)
                    : qr.getOutputWord();

            // First check for I/O non-determinism
            Word<O> prevObservation = queryDoneCache.putIfAbsent(iPrefix, oPrefix);
            if (prevObservation != null && !prevObservation.equals(oPrefix)) {
                if (model.getOutput(curr, i) == null) {
                    // this transition has previously been deleted
                    // so update querydonecache and continue
                    queryDoneCache.put(iPrefix, oPrefix);
                } else {
                    log.severe("Retrying Inconsistent query response in query " + qr.getInputWord().toString() + "\n"
                            + "Input " + j + ": expected - " + model.getOutput(curr, i) + " //// Got - "
                            + o.toString());
                    handleNonDeterminism(curr, i, iPrefix);
                    return false;
                }
            }

            // Second check for I/O contradictions that indicate we have missed memory
            if (model.getOutput(curr, i) != null && !o.equals(model.getOutput(curr, i))) {
                log.warning("Observed I/O contradicts state memory classifications for state " + curr.getId()
                        + " after input " + i + ". Likely missing state memory in monitor set. ");
                // For now we cease exploration beyond this query.
                // TODO possibly revise state memory classifications
                if (queryQueue.removeIf(f -> iPrefix.isPrefixOf(f))) {
                    this.queryBlacklist.add(iPrefix);
                    log.info("Updated queryQueue to prevent exploration beyond this contradiction.");
                }
                return true;
            }

            FastMealyMemState<O> nxt = model.getSuccessor(curr, i);

            QueryResponseMeta qrj = null;
            try {
                qrj = qr.getQrs().get(j);
            } catch (Exception e) {
                // If we get an index out of bounds exception here, either:
                // 1. we weren't able to obtain the right number of snapshots for the given size
                // of the I/O sequence. // because the response to our final input in the query
                // was "empty"
                // OR
                // 2. There was a fuckup

                // If 1, then assume it is a new state insofar as we add to the query queue,
                // n queries where n = |I|, curr prefix, and suffix = for all input set
                // These queries should then give us a snapshot for the current i/o seq, which
                // in this iteration we will now throw away.

                // If 2. then o is not "empty", it will be null, so determine this accordingly
                // and retry query


                // If this prefix of the input sequence is already defined in the model, we don't
                // need to handle the error again in this iteration.
                if(nxt != null) continue;

                if (Utils.isEmpty(o.toString(), config.emptyOutputs)
                        || this.CTR_SNAPSHOT_FAIL >= this.MAX_SNAPSHOT_FAIL) {
                    log.info("No snapshots obtained for input/output pair (" + i.toString() + "/" + o.toString()
                            + "), queueing new queries.");
                    if( iPrefix.size() == qr.getInputWord().size() ) {
                        // We didn't get a snapshot for the final input of the query. 
                        ArrayList<Word<I>> newQueries = new ArrayList<>();
                        for (I suffix : model.getInputAlphabet()) {
                            Word<I> newQuery = iPrefix.append(suffix);
                            newQueries.add(newQuery);
                        }
                        queueQueryList(newQueries, this.queryQueue);
                        this.CTR_SNAPSHOT_FAIL = 0;
                        return true;
                    } else {
                        log.info("Not possible to obtain snapshot for input, mapping as loopback");
                        model.addTransition(curr, i, curr, o);
                        this.CTR_SNAPSHOT_FAIL = 0;
                        return true;
                    }
                } else {

                    // Queries are cut off after a disabled output is observed so this is ok
                    // Otherwise, true fuck up so return false and retry.
                    if (Utils.isDisabled(o.toString(), config.disableOutputs) && model.getDisableState() != null) {
                        if (nxt == null)
                            model.addTransition(curr, i, model.getDisableState(), o);
                        return true;
                    } else {
                        // TODO what do we do if this is a bootstrap flow?
                        log.severe("No snapshots obtained for input/output pair (" + i.toString() + "/" + o.toString()
                                + "), retrying...");
                        this.CTR_SNAPSHOT_FAIL++;
                        return false;
                    }
                }
            }

            // Check if our model has a transition from curr, at input i
            if (nxt != null) {
                // We already have this transtion in the model
                model.addStateMetaDataMap(qr.getQrs().get(j));
                curr = nxt;
            } else {
                // New information

                if (Utils.isDisabled(o.toString(), config.disableOutputs)) {
                    model.addTransition(curr, i, model.getDisableState(), o);
                    model.addStateMetaDataMap(qr.getQrs().get(j));
                    break;
                
                // If this snapshot was taken at a socket close/shutdown,
                // map this transition to the disable state.
                } else if (qr.getQrs().get(j).getType().equals("CLOSE")) {
                    model.addTransition(curr, i, model.getDisableState(), o);
                    break;
                } else {

                    // New transition

                    // Get the state memory at the snapshot pointed to by qrj
                    HashMap<AllocOffset, Optional<byte[]>> currSM = buildStateMem(qrj);

                    FastMealyMemState<O> ss = memOracle.getEqualState(currSM, iPrefix, qr.isHappyFlow());

                    if (ss == null) {
                        // create new state and transition from curr
                        curr = createNewState(qr, curr, j, i, o, currSM);
                    } else {
                        if (qr.isHappyFlow()) {
                            log.warning("No differing memory in a happy-flow transition (could be a loopback).");
                        }
                        curr = mapExistingState(qr, curr, j, i, o, ss);
                    }
                }
            }
        }
        return true;
    }

    private void handleNonDeterminism(FastMealyMemState<O> curr, I i, Word<I> iPrefix) {
        // Only revise the model if we have attempted this query
        // MAX_INCONSISTENT_ATTEMPT times
        if (this.CTR_INCONSISTENT < this.MAX_INCONSISTENT_RETRIES) {
            this.CTR_INCONSISTENT++;
            return;
        }
        FastMealyMemState<O> toDetach = model.getSuccessor(curr, i);
        log.severe("Deleting transition and states (if required) - StateID: " + curr.getId() + " Input: " + i.toString()
                + " --> StateID: " + toDetach.getId());
        model.setTransition(curr, i, null);
        // remove state if detatched
        // if not connected need to remove all other states
        if (toDetach != null && !toDetach.isBaseState() && !this.model.isConnected(toDetach)) {
            this.model.removeDetachedStates();
            if (queryQueue.removeIf(f -> iPrefix.isPrefixOf(f)))
                log.info("Updated queryQueue");
            if (queryDoneCache.keySet().removeIf(f -> iPrefix.isPrefixOf(f)))
                log.info("Updated queryDoneCache");
        }
        this.CTR_INCONSISTENT = 0;
    }

    private FastMealyMemState<O> mapExistingState(QueryResponse<I, O> qr, FastMealyMemState<O> curr, int j, I i, O o,
            FastMealyMemState<O> simState) throws Exception {
        model.addTransition(curr, i, simState, o);
        model.addStateMetaDataMap(qr.getQrs().get(j));
        // we are now at that pre-existing state
        log.fine("Mapping state " + curr.getSID() + " to state " + simState.getSID());
        curr = simState;
        Utils.drawModel(this.config, this.model);
        CompactMealy<I,O> minimisedModel = this.model.minimise();
        Utils.drawModel(config, minimisedModel, "minimised-test.dot", false);
        return curr;
    }

    private FastMealyMemState<O> createNewState(QueryResponse<I, O> qr, FastMealyMemState<O> curr, int j, I i, O o,
            HashMap<AllocOffset, Optional<byte[]>> sm) throws FileNotFoundException, IOException, InterruptedException {
        FastMealyMemState<O> ns = model.addState();
        ns.setIsBaseState(qr.isHappyFlow());
        model.addStateMemory(ns, sm);
        model.addStateMetaDataMap(qr.getQrs().get(j));
        model.addTransition(curr, i, ns, o);
        // Add new queries to queue
        ArrayList<Word<I>> newQueries = new ArrayList<>();
        for (I suffix : model.getInputAlphabet()) {
            newQueries.add(qr.getInputWord().subWord(0, j + 1).append(suffix));
        }
        queueQueryList(newQueries, this.queryQueue);
        // we are now at that new state
        curr = ns;
        Utils.drawModel(this.config, this.model);
        model.printMemMap(config.getOutputDir() + "/mem-classifications.dump");
        return curr;
    }

    private HashMap<AllocOffset, Optional<byte[]>> buildStateMem(QueryResponseMeta qrj) throws Exception {
        // TODO could probably cache the EntryLists instead of reconstructing every time
        return (this.memInterface.run(
                new Snapshot(qrj.getTimestamp(), Paths.get(qrj.getDump_file()),
                        qrj.getType() == "READ" ? Type.READ : Type.WRITE, qrj.getCount()),
                MallocEntry.buildMallocEntryList(Paths.get(qrj.getMalloc_log())), model.getAddrSet().getHeapBase(),
                model.getAddrSet().getMonitorAddrsMap()));
    }

    private boolean queueQueryList(ArrayList<Word<I>> newQueries, LinkedList<Word<I>> queryQueue) {
        boolean added = false;
        for (Word<I> newQuery : newQueries) {
            if (model.getSuccessor(model.getInitialState(), newQuery) != null) continue;
            if(queryBlacklist.stream().anyMatch(i -> i.isPrefixOf(newQuery))) continue;
            if (!queryQueue.contains(newQuery)) {
                if (!queryQueue.stream().anyMatch(q -> newQuery.isPrefixOf(q))) {
                    queryQueue.add(newQuery);
                    added = true;
                }
            }
        }
        // Everytime we add a new list of queries to the queue, reorder.
        Collections.sort(queryQueue, (q1, q2) -> model.getQueryLength(q1) - model.getQueryLength(q2));
        return added;
    }

    private void doCheckMerge() throws Exception {

        log.info("State merge check round 1: LOW confidence addresses only.");
        processIOEquivalentGroup_ConnectedLowConfidence();

        log.info(
                "State merge check round 2: Any connected I/O equivalent states to depth " + config.ioEquivalenceDepth);
        processIOEquivalentGroup_ConnectedConfigurableDepth();

        if (config.resetInputs != null) {
            log.info("State merge check round 3: RESET like inputs");
            processIOEquivalentGroup_ResetStates();
        }

        // log.info("State merge check round four: Any I/O equivalent states to depth "
        // + config.ioEquivalenceDepth);
        // processIOEquivalentGroupConfigurableDepth();
    }

    private void doCheckBoundedMerge(Word<I> currQuery) {
        if(config.explorationBound <= 0 || currQuery.length() <= config.explorationBound) return;
        ArrayList<Integer> visitedStates = this.model.getStateIDsOnPath(currQuery);
        for(Pair<Integer, Integer> mergeCandidate : this.mergeCandidates) {
            int mergeStateID = mergeCandidate.getValue1();
            if(visitedStates.contains(mergeStateID)
                && visitedStates.size() - visitedStates.indexOf(mergeStateID) > config.explorationBound)
                mergeTaintPositiveBounded(mergeCandidate);
        }
    }

    private void mergeTaintPositiveBounded(Pair<Integer, Integer> mergeCandidate) {
        int baseID = mergeCandidate.getValue0();
        int toMergeID = mergeCandidate.getValue1();

        Word<I> sepWord = NearLinearEquivalenceTest.findSeparatingWord(this.model,
                this.model.getStateBySID(baseID), this.model.getStateBySID(toMergeID),
                this.model.getInputAlphabet(), true);

        if(sepWord != null) {
            return;
            // log.info("Not merging states [" + baseID + ", " + toMergeID + "], due to separating word: " +  sepWord.toString());
        } else {
            //TODO remove differentiating memory confirmed conditional
            log.info("Merging previously memory distinct states [" + baseID + ", " + toMergeID + "] as no distinguishing I/O found within depth bound of " + config.explorationBound);
            this.model.mergeState(this.model.getStateBySID(baseID), this.model.getStateBySID(toMergeID));
        }
    }

    private void processIOEquivalentGroup_ResetStates() throws Exception {
        Map<Pair<HashSet<I>, List<Flow<I, O>>>, List<FastMealyMemState<O>>> stageOne = model.groupStatesByIOIncoming(1);
        for(Pair<HashSet<I>, List<Flow<I, O>>> k : stageOne.keySet()) {
            if(k.getValue0().stream().allMatch(i -> config.resetInputs.contains(i))) {
                List<FastMealyMemState<O>> ioEqGroup = stageOne.get(k);
                ioEqGroup.removeIf(s -> s.getId()==-1);
                ioEqGroup.removeIf(s -> this.model.getInitialState().equals(s));
                if(ioEqGroup.size() < 2) continue;
                mergeIOEquivalentStates(ioEqGroup, false, false);
            }
        }
    }

    private void processIOEquivalentGroup_ConnectedLowConfidence() throws Exception {
        //First attempt to merge any states I/O equivalent to depth 1, and differ by only low confidence addresses
        Map<List<Flow<I, O>>, List<FastMealyMemState<O>>> stageOne = model.groupStatesByIO(1);
        _processIOEquivalentGroup(stageOne, true, true);
    }

    private void processIOEquivalentGroup_ConnectedConfigurableDepth() throws Exception {
        //Now try merge any state two connected states, I/O equivalent to specified depth
        Map<List<Flow<I, O>>, List<FastMealyMemState<O>>> stageTwo = model.groupStatesByIO(config.ioEquivalenceDepth);
        _processIOEquivalentGroup(stageTwo, false, true);
    }

    private void processIOEquivalentGroup_ConfigurableDepth() throws Exception {
        //Now try merge any state I/O equivalent to specified depth
        Map<List<Flow<I, O>>, List<FastMealyMemState<O>>> stageTwo = model.groupStatesByIO(config.ioEquivalenceDepth);
        _processIOEquivalentGroup(stageTwo, false, false);
    }

    private void _processIOEquivalentGroup(Map<List<Flow<I, O>>, List<FastMealyMemState<O>>> groups, boolean lowConfidenceOnly, boolean connected) throws Exception {
        for(List<Flow<I,O>> stateGroup : groups.keySet()) {
            List<FastMealyMemState<O>> ioEqGroup = groups.get(stateGroup);
            //Removes any states from the group which were deleted by the previous merge round
            ioEqGroup.removeIf(s -> s.getId()==-1);
            //Removes the initial state, which will not have a memory mapping as we have no guarantee state memory has been allocated by this point
            ioEqGroup.removeIf(s -> this.model.getInitialState().equals(s));
            if(ioEqGroup.size() < 2) continue;
            mergeIOEquivalentStates(ioEqGroup, lowConfidenceOnly, connected);
        }
    }

    //Iteratively processes a group of IO equivalent states, merging them based on "connectedness" and "differing memory" properties
    private void mergeIOEquivalentStates(List<FastMealyMemState<O>> ioEqGroup, boolean lowConfidenceOnly, boolean connected) throws Exception {

        StringBuilder sb = new StringBuilder();

        //Only try merging states which are connected by one hop.
        int connectedHops = connected ? 1 : 0;

        while(true) {
            //Remove any "dead" states, merged in previous round
            ioEqGroup.removeIf(s -> s.getId()==-1);
            //No more states to process, so return
            if(ioEqGroup.size() <= 1) return;

            //Copy the list of states
            List<FastMealyMemState<O>> mergeGroup = new ArrayList<>(ioEqGroup);

            // We choose the base state of the group to be the one from which 
            // the most other states in the group are reachable from
            FastMealyMemState<O> base = model.getBaseState(mergeGroup, connectedHops);

            //If no base can be found in the group, don't try merging anything
            if(base == null)  return;

            // Remove the base and all non-base-connecting states
            mergeGroup.remove(base);

            // Don't bother trying to merge states which are already fully defined
            mergeGroup.removeIf(m -> model.isFullyDefined(m));
            if(connected) mergeGroup.removeIf(s -> !model.isConnected(base, s, connectedHops));

            if(mergeGroup.isEmpty()) return;

            sb.append("State: ["+base.getSID()+"] with merge candidates [");
            mergeGroup.forEach(s -> sb.append(s.getSID() + ", ")); sb.replace(sb.length()-2, sb.length(), "]");
            log.info(sb.toString()); sb.setLength(0);
            
            HashMap<FastMealyMemState<O>, ArrayList<AllocOffset>> stateBaseDiffs = memOracle.nWayMemDiff(base, mergeGroup);
            assert(stateBaseDiffs.size() > 0);
            for(FastMealyMemState<O> stateToMerge : stateBaseDiffs.keySet()) {
                if(stateToMerge.getId() == -1) continue;
                ArrayList<AllocOffset> stateDiffs = stateBaseDiffs.get(stateToMerge);
                if(lowConfidenceOnly && !stateDiffs.stream().allMatch(d -> this.model.getConfidence(d).equals(Confidence.LOW))) {
                    this.addMergeCandidate(new Pair<>(base.getSID(), stateToMerge.getSID()));
                    log.info("States differ by non-low confidence memory, continuing.");
                    continue;
                }
                // We will try to merge based on the results of taint analysis of differing memory
                boolean didMerge = memOracle.mergeTaintState(base, stateToMerge, stateDiffs);
                if(didMerge) ioEqGroup.remove(stateToMerge);
            }
            ioEqGroup.remove(base);
        }
    }
    
    public boolean answerQueryUpdateModel(Word<I> currQuery, TainterConfig tc, boolean allowLoopbacks) throws Exception {
        // Check if given query will refine model
        if (tc == null && model.getSuccessor(model.getInitialState(), currQuery) != null)
            return false;
        // Check if at any point the output suffix contains a connclosed/disable ouput
        if (config.disableOutputs != null) {
            Word<O> preOutput = model.computeOutput(currQuery);
            if (preOutput.stream().anyMatch(o -> Utils.isDisabled(o.toString(), config.disableOutputs)))
                return false;
        }
        //Check if query loops states
        if(!allowLoopbacks && model.doesLoopback(currQuery)) return false;

        QueryResponse<I, O> qrs = null;
        this.CTR_INCONSISTENT = 0;
        this.CTR_SNAPSHOT_FAIL = 0;
        while (true) {
            try {
                if (config.resetTargetEachQuery) {
                    this.target.launchTarget(true);
                    if (!config.signalPtraceAttach) {
                      oracle.setUp();
                    }
                }
                if(tc == null) {
                    qrs = oracle.answerQuery(currQuery);
                } else {
                    qrs = oracle.answerQuery(currQuery, tc);
                }
                if(qrs != null && updateModel(qrs)) {
                    //delete the snapshots used for this query
                    if(tc == null) oracle.cleanup();
                    break;
                } else {
                    oracle.cleanup();
                    stats.failedCounter++;
                }
            } catch (EOFException e) {
                log.severe("Snapshot read error, retrying query.");
            } catch (SULException e) {
                log.severe(e.getMessage());
                log.severe("Attempting to relaunch target");
                if (target.launchTarget(true) && !config.signalPtraceAttach) {
                  oracle.setUp();
                } else {
                  throw e;
                }
            }
        }
        return true;
    }
    
    public void learn() throws Exception {

        int currentPhaseQuerySize = 3;
        while (true) { 
            if(this.queryQueue.isEmpty()) {
                Utils.drawModel(config, model);
                ArrayList<Word<I>> remainingQueries = this.model.getQueriesIfIncomplete();
                if(!queueQueryList(remainingQueries, this.queryQueue)) {
                    doCheckMerge();
                    return;
                }
            }
            //We have performed all queries of the currentPhaseQuerySize, so perform a merge and termination check
            if (model.getQueryLength(this.queryQueue.get(0)) > currentPhaseQuerySize) {
                // first double check the model is fully defined with queries up to length currentPhaseQuerySize
                ArrayList<Word<I>> remainingQueries = this.model.getQueriesIfIncomplete();
                if (!remainingQueries.isEmpty() && model.getQueryLength(remainingQueries.get(0)) <= currentPhaseQuerySize) {
                    if(queueQueryList(remainingQueries, this.queryQueue)) continue;
                }
                doCheckMerge();
                Utils.drawModel(config, model);
                remainingQueries = this.model.getQueriesIfIncomplete();
                queueQueryList(remainingQueries, this.queryQueue);
                if(model.getQueryLength(this.queryQueue.get(0)) > currentPhaseQuerySize) {
                    currentPhaseQuerySize+=1;
                    // If we are time bounding learning, then check elapsed time and return if bound has been reached
                    if(config.timeBound > 0 && stats.getElapsedLearningTimeMinutes() > (0.8 * config.timeBound)) {
                        model.removeUndefinedStates();
                        return;
                    }
                }
            } else {
                Word<I> currQuery = this.queryQueue.removeFirst();
                doCheckBoundedMerge(currQuery); //TODO: This is pretty inneficient so change at some point
                if(answerQueryUpdateModel(currQuery, null, false))
                    stats.membershipCounter++;
            }
        }
    }

	public void addMergeCandidate(Pair<Integer, Integer> mergeCandidate) {
        this.mergeCandidates.add(mergeCandidate);
	}

}
