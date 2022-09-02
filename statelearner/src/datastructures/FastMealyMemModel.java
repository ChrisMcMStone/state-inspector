package datastructures;

import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.base.Optional;
import com.google.common.collect.Table;
import com.google.common.collect.TreeBasedTable;

import org.javatuples.Pair;
import org.javatuples.Triplet;

import datastructures.StateAddrSet.Confidence;
import learner.Config;
import learningalgorithm.QueryResponseMeta;
import net.automatalib.automata.base.fast.AbstractFastMutableDet;
import net.automatalib.automata.graphs.UniversalAutomatonGraphView;
import net.automatalib.automata.transducers.MutableMealyMachine;
import net.automatalib.automata.transducers.StateLocalInputMealyMachine;
import net.automatalib.automata.transducers.impl.MealyTransition;
import net.automatalib.automata.transducers.impl.compact.CompactMealy;
import net.automatalib.util.graphs.ShortestPaths;
import net.automatalib.util.automata.minimizer.paigetarjan.PaigeTarjanMinimization;
import net.automatalib.words.Alphabet;
import net.automatalib.words.Word;
import utils.Flow;
import utils.Utils;

/**
 * A fast implementation of a Mealy machine.
 *
 * @param <I> input symbol class.
 * @param <O> output symbol class.
 *
 */
public class FastMealyMemModel<I, O>
        extends AbstractFastMutableDet<FastMealyMemState<O>, I, MealyTransition<FastMealyMemState<O>, O>, Void, O>
        implements MutableMealyMachine<FastMealyMemState<O>, I, MealyTransition<FastMealyMemState<O>, O>, O>,
        StateLocalInputMealyMachine<FastMealyMemState<O>, I, MealyTransition<FastMealyMemState<O>, O>, O> {

    /**
     *
     */
    private static final long serialVersionUID = 4252502013866759745L;

    /**
     * Constructor. Initializes a new (empty) Mealy machine with the given input
     * alphabet.
     *
     * @param alphabet the input alphabet.
     */

    private StateAddrSet addrSet;
    private Table<Integer, AllocOffset, Optional<byte[]>> modelMemTable;
    // Maps stateID to list of merged state details including (differing addrs +
    // vals, input prefix)
    private HashMap<Integer, ArrayList<MergedState<I>>> mergedStatesMap;
    private HashMap<Word<I>, HashSet<QueryResponseMeta>> stateMetaDataMap;
    private FastMealyMemState<O> disableState = null;
    private Integer statememKeyID = 0;
    private String reprLogFilename;

    public FastMealyMemModel(Alphabet<I> alphabet) {
        super(alphabet);
        this.addrSet = new StateAddrSet();
        this.addInitialState();
        this.getInitialState().setIsBaseState(true);
        this.modelMemTable = TreeBasedTable.create();
        this.mergedStatesMap = new HashMap<>();
        this.stateMetaDataMap = new HashMap<>();
        //Set up the disabled state
        FastMealyMemState<O> ns = this.addState();
        // Don't give the disabled state a memory classifier, as this can cause problems
        this.setDisableState(ns);
        for (I i : this.getInputAlphabet()) {
            this.addTransition(ns, i, ns, (O)"x");
        }
    }

    @Override
    public FastMealyMemState<O> getSuccessor(MealyTransition<FastMealyMemState<O>, O> transition) {
        return transition.getSuccessor();
    }

    @Override
    public O getTransitionOutput(MealyTransition<FastMealyMemState<O>, O> transition) {
        return transition.getOutput();
    }

    @Override
    public MealyTransition<FastMealyMemState<O>, O> createTransition(FastMealyMemState<O> successor, O properties) {
        return new MealyTransition<>(successor, properties);
    }

    @Override
    public void setTransitionOutput(MealyTransition<FastMealyMemState<O>, O> transition, O output) {
        transition.setOutput(output);
    }

    @Override
    protected FastMealyMemState<O> createState(Void property) {
        FastMealyMemState<O> fsm = new FastMealyMemState<>(inputAlphabet.size(), statememKeyID);
        return fsm;
    }

    public FastMealyMemState<O> addState() {
        statememKeyID++;
        FastMealyMemState<O> s = super.addState();
        return s;
    }

    public StateAddrSet getAddrSet() {
        return addrSet;
    }

    public void setAddrSet(StateAddrSet addrSet) {
        this.addrSet = addrSet;
    }

    public FastMealyMemState<O> getDisableState() {
        return disableState;
    }

    public void setDisableState(FastMealyMemState<O> disableState) {
        this.disableState = disableState;
    }

    public void addStateMemory(FastMealyMemState<O> state, HashMap<AllocOffset, Optional<byte[]>> sm) {
        for (AllocOffset colKey : sm.keySet()) {
            this.modelMemTable.put(state.getSID(), colKey, sm.get(colKey));
        }
    }

    public void printMemMap(String filename) throws IOException {
        for (FastMealyMemState<O> state : this.getStates()) {
            StringBuilder sb = new StringBuilder();
            for (AllocOffset ao : this.modelMemTable.columnKeySet()) {
                Optional<byte[]> val = this.modelMemTable.get(state.getSID(), ao);
                if (val == null)
                    continue;
                sb.append("\n" + ao.toString() + " : "
                        + (val.isPresent() ? Utils.bytesToHex(val.get()): "??"));
            }
            FileWriter memMapFile = new FileWriter(filename + "." + state.getSID());
            memMapFile.write(sb.toString());
            memMapFile.close();
        }
    }

    public void removeStateAndMemory(FastMealyMemState<O> fastMealyMemState) {

        this.modelMemTable.row(fastMealyMemState.getSID()).clear();
        this.removeState(fastMealyMemState, null);
    }

    public HashMap<AllocOffset, Optional<byte[]>> getMemMapAtState(FastMealyMemState<O> state) {
        return new HashMap<>(this.modelMemTable.row(state.getSID()));
    }

    public List<FastMealyMemState<O>> getMemoryDefinedStates() {
        return this.getStates().stream().filter(s -> !this.modelMemTable.row(s.getSID()).isEmpty())
                .collect(Collectors.toList());
    }

    public Confidence getConfidence(AllocOffset addr) {
        return this.addrSet.getAddrConfidenceMap().get(addr);
    }

    public boolean updateAddrSetConfidences(AllocOffset addr, Confidence newConfidence) throws Exception {
        return updateAddrSetConfidences(addr, newConfidence, null, false);
    }

    public boolean updateAddrSetConfidences(AllocOffset addr, Confidence newConfidence,
            HashMap<AllocOffset, Optional<byte[]>> stateMem, boolean positive) throws Exception {

        Confidence currAddrConfidence = this.addrSet.getAddrConfidenceMap().get(addr);

        // Don't change the confidence if it's already been confirmed
        if (currAddrConfidence.equals(Confidence.CONFIRMED))
            return false;

        // Dont replace conditional state mem with low confidence
        if (newConfidence.equals(Confidence.LOW) && currAddrConfidence.equals(Confidence.CONDITIONAL))
            return false;

        if (newConfidence.equals(Confidence.CONDITIONAL)) {
            if (stateMem == null || stateMem.isEmpty()) {
                throw new Exception("Tried to set a CONFIRMED_CONDITIONAL confidence without the state mem conditions");
            } else {
                this.addrSet.updateConfidence(addr, newConfidence);
                if (positive) {
                    this.addrSet.updateConfidenceDependencyMapConfirmed(addr, stateMem);
                } else {
                    this.addrSet.updateConfidenceDependencyMapNegative(addr, stateMem);
                }
            }
        } else {
            this.addrSet.updateConfidence(addr, newConfidence);
        }
        return true;
    }

    public boolean isConnected(FastMealyMemState<O> toCheck) {
        return isConnected(this.getInitialState(), toCheck, new HashSet<>(), null);
    }

    public boolean isConnected(FastMealyMemState<O> start, FastMealyMemState<O> toCheck, Integer maxDepth) {
        return isConnected(start, toCheck, new HashSet<>(), maxDepth);
    }

    // When called with maxDepth == null there is no depth bound
    private boolean isConnected(FastMealyMemState<O> start, FastMealyMemState<O> toCheck,
            HashSet<FastMealyMemState<O>> checked, Integer maxDepth) {
        if (maxDepth != null && maxDepth <= 0)
            return false;
        checked.add(start);
        for (I i : this.getLocalInputs(start)) {
            FastMealyMemState<O> suc = this.getSuccessor(start, i);
            if (suc != null) {
                if (checked.contains(suc))
                    continue;
                if (suc.equals(toCheck)) {
                    return true;
                } else {
                    if (isConnected(suc, toCheck, checked, maxDepth != null ? maxDepth - 1 : null))
                        return true;
                }
            }
        }
        return false;
    }

    public boolean doesLoopback(Word<I> query) {
        FastMealyMemState<O> state = this.getInitialState();
        for(int i=0; i < query.length(); i++) {
            FastMealyMemState<O> nxtState = this.getSuccessor(state, query.getSymbol(i));
            if (nxtState == null)
                return false;
            if (nxtState.equals(state))
                return true;
            state = nxtState;
        }
        return false;
    }

    public ArrayList<Word<I>> getQueriesIfIncomplete() {
        ArrayList<Word<I>> queries = new ArrayList<>();
        for (FastMealyMemState<O> s : this.getMemoryDefinedStates()) {
            Word<I> pathToState = null;
            for (I i : this.getInputAlphabet()) {
                if (!this.getLocalInputs(s).contains(i)) {
                    if (pathToState == null) {
                        pathToState = getPath(this.getInitialState(), s, new HashSet<>(), Word.epsilon());
                    }
                    Word<I> newQuery = pathToState.append(i);
                    queries.add(newQuery);
                }
            }
        }
        Collections.sort(queries, (q1, q2) -> getQueryLength(q1) - getQueryLength(q2));
        return queries;
    }

    public boolean isFullyDefined(FastMealyMemState<O> start) {
        return isFullyDefined(start, new HashSet<>());
    }

    private boolean isFullyDefined(FastMealyMemState<O> start, HashSet<FastMealyMemState<O>> checked) {
        checked.add(start);
        for (int i = 0; i < this.getInputAlphabet().size(); i++) {
            if (start.getTransitionObject(i) == null) {
                return false;
            } 
            FastMealyMemState<O> suc = this.getSuccessor(start, this.getInputAlphabet().getSymbol(i));
            if(checked.contains(suc)) {
                continue;
            } else {
                if(!isFullyDefined(suc, checked)) return false;
            }
        }
        return true;
    }

    // When called with maxDepth == null there is no depth bound
    private Word<I> getPath(FastMealyMemState<O> start, FastMealyMemState<O> toCheck,
            HashSet<FastMealyMemState<O>> checked, Word<I> path) {
        checked.add(start);
        for (I i : this.getLocalInputs(start)) {
            Word<I> thisPath = path.append(i);
            FastMealyMemState<O> suc = this.getSuccessor(start, i);
            if (suc != null) {
                if (checked.contains(suc))
                    continue;
                if (suc.equals(toCheck)) {
                    return thisPath;
                } else {
                    Word<I> recPath = getPath(suc, toCheck, checked, thisPath);
                    if (recPath != null)
                        return recPath;
                }
            }
        }
        return null;
    }

    public HashSet<I> getIncomingInputs(FastMealyMemState<O> target) {
        HashSet<I> inputs = new HashSet<I>();
        for(FastMealyMemState<O> state : this.getStates()) {
            if(state.getSID() == target.getSID()) continue;
                for (I i : this.getLocalInputs(state)) {
                    FastMealyMemState<O> suc = this.getSuccessor(state, i);
                    if(suc.getSID() == state.getSID()) continue;
                    if(suc.getSID() == target.getSID()) inputs.add(i);
                }
        }
        return inputs;
    }

    public Map<Pair<HashSet<I>, List<Flow<I, O>>>, List<FastMealyMemState<O>>> groupStatesByIOIncoming(int ioEquivalenceDepth) {

            Map<Pair<HashSet<I>, List<Flow<I, O>>>, List<FastMealyMemState<O>>> groupedStatesInput = this.getStates().stream()
                    .collect(Collectors.groupingBy(s -> new Pair<>(getIncomingInputs(s), this.getLocalInputsOutputs(s, null, ioEquivalenceDepth))));

            // Filter out all groups of states which don't have the minimum ioEquivalence
            // info
            groupedStatesInput.keySet()
                    .removeIf(flowList -> flowList.getValue1().size() != Math.pow(this.getInputAlphabet().size(), ioEquivalenceDepth));
            return groupedStatesInput;
    }

    public Map<List<Flow<I, O>>, List<FastMealyMemState<O>>> groupStatesByIO(int ioEquivalenceDepth) {

        Map<List<Flow<I, O>>, List<FastMealyMemState<O>>> groupedStates = this.getStates().stream()
                .collect(Collectors.groupingBy(s -> this.getLocalInputsOutputs(s, null, ioEquivalenceDepth)));

        // Filter out all groups of states which don't have the minimum ioEquivalence
        // info
        groupedStates.keySet()
                .removeIf(flowList -> flowList.size() != Math.pow(this.getInputAlphabet().size(), ioEquivalenceDepth));

        return groupedStates;
    }

    public FastMealyMemState<O> getStateBySID(int sid) {
        for (FastMealyMemState<O> s : this.getStates()) {
            if( s.getSID() == sid)
                return s;
        }
        return null;
    }

    public List<Flow<I, O>> getLocalInputsOutputs(FastMealyMemState<O> state, Flow<I, O> pref, int queryDepth) {
        if (queryDepth <= 0)
            return null;
        final Alphabet<I> alphabet = getInputAlphabet();
        final int alphabetSize = alphabet.size();
        final List<Flow<I, O>> result = new ArrayList<>();
        for (int i = 0; i < alphabetSize; i++) {
            Flow<I, O> f = new Flow<>();
            if (pref != null) {
                f.setInputs(new ArrayList<>(pref.getInputs()));
                f.setOutputs(new ArrayList<>(pref.getOutputs()));
            }
            if (state.getTransitionObject(i) == null) {
                // If we don't have all inputs defined at this state, return empty list
                // TODO optionalise this if we want this method to be used for other purposes
                result.clear();
                return result;
            } else {
                FastMealyMemState<O> suc = this.getSuccessor(state, alphabet.getSymbol(i));
                f.getInputs().add(alphabet.getSymbol(i));
                f.getOutputs().add(state.getTransitionObject(i).getOutput());
                if (queryDepth > 1) {
                    List<Flow<I, O>> recResult = getLocalInputsOutputs(suc, f, queryDepth - 1);
                    if (recResult != null)
                        result.addAll(recResult);
                } else {
                    result.add(f);
                }
            }
        }
        return result;
    }

    public boolean mergeState(FastMealyMemState<O> base, FastMealyMemState<O> stateToMerge) {
        ArrayList<FastMealyMemState<O>> statesToMerge = new ArrayList<>();
        statesToMerge.add(stateToMerge);
        return mergeStates(base, statesToMerge);
    }

    private boolean mergeStates(List<FastMealyMemState<O>> statesToMerge) {
        assert (statesToMerge.size() > 1);
        return mergeStates(statesToMerge.get(0), statesToMerge);
    }

    public boolean mergeStates(FastMealyMemState<O> base, List<FastMealyMemState<O>> statesToMerge) {
        for (FastMealyMemState<O> mergeState : statesToMerge) {
            if (mergeState.equals(base))
                continue; // essential check as we support non specified base
            this.removeState(mergeState, base);
        }
        // Remove any "detatched" states as a result of a merge
        this.removeDetachedStates();
        return true;
    }

    public void removeDetachedStates() {
        Iterator<FastMealyMemState<O>> it = this.getStates().iterator();
        while (it.hasNext()) {
            FastMealyMemState<O> state = it.next();
            if (state.equals(this.getInitialState()))
                continue;
            if (!isConnected(state)) {
                this.removeStateAndMemory(state);
                it = this.getStates().iterator();
            }
        }
    }

    public FastMealyMemState<O> getBaseState(List<FastMealyMemState<O>> states, int connectedHops) {

        if (states == null || states.size() == 0)
            return null;

        //TODO implement preferential selection of a happy state as the base state
        // if hops = 0, we don't mandate the base state to be connected to the other states
        // so just find the state with the shortest path from the initial state
        if (connectedHops == 0) {
            //This is pretty inneficient but guaranteed to be correct & computation shouldn't happen very often. 
            UniversalAutomatonGraphView<FastMealyMemState<O>, I, MealyTransition<FastMealyMemState<O>, O>, Void, O, FastMealyMemModel<I, O>> x = MealyGraphView.create(this);
            return states.stream().min(Comparator.comparing(o -> ShortestPaths.shortestPath(x, this.getInitialState(), this.getStates().size(), o).size())).orElse(null);
        } else {
            FastMealyMemState<O> base = null;
            long conCount = 0;
            for (FastMealyMemState<O> test : states) {
                long curCount = states.stream().filter(is -> !is.equals(test)).map(a -> isConnected(test, a, connectedHops))
                        .filter(p -> p == true).count();
                if (curCount > conCount) {
                    conCount = curCount;
                    base = test;
                }
            }
            return base;
        }
    }

    public Pair<Boolean, Integer> isReachableWithInput(FastMealyMemState<O> testState, Word<I> input) {
        FastMealyMemState<O> currState = this.getInitialState();
        for (int i = 0; i < input.length(); i++) {
            FastMealyMemState<O> suc = this.getSuccessor(currState, input.getSymbol(i));
            if (suc == null)
                return new Pair<>(false, 0);
            if (suc.equals(testState))
                return new Pair<>(true, i);
            currState = suc;
        }
        return new Pair<>(false, 0);
    }

    public String getReprLogFilename() {
        return reprLogFilename;
    }

    public void setReprLogFilename(String reprLogFilename) {
        this.reprLogFilename = reprLogFilename;
    }

    public Collection<HashMap<AllocOffset, Optional<byte[]>>> getConfirmedConditionAddrSet(AllocOffset dAddr) {
        return this.getAddrSet().getConfidenceDependencyMapConfirmed(dAddr);
    }

    public Collection<HashMap<AllocOffset, Optional<byte[]>>> getNegativeConditionAddrSet(AllocOffset dAddr) {
        return this.getAddrSet().getConfidenceDependencyMapNegative(dAddr);
    }

    public CompactMealy<I,O> minimise() throws Exception {

        //Can't use hopcroft minimisation on partial automata
        //CompactMealy<I,O> test2 = HopcroftMinimization.minimizeMealy(this);
        return PaigeTarjanMinimization.minimizeMealy(this);
    }
    
    private Set<Triplet<I, O, FastMealyMemState<O>>> getAllStateTransitions(FastMealyMemState<O> s, boolean excludeLoopbacks) {
        Set<Triplet<I, O, FastMealyMemState<O>>> res = new HashSet<>();
        this.getLocalInputs(s).stream()
                .forEach(i -> res.addAll(this.getTransitions(s, i).stream()
                .filter(t -> excludeLoopbacks && !t.getSuccessor().equals(s))
                .map(t -> new Triplet<>(i, t.getOutput(), t.getSuccessor()))
                .collect(Collectors.toList())));
        return res;
    }

    public ArrayList<Integer> getStateIDsOnPath(Word<I> input) {
        ArrayList<Integer> stateIDs = new ArrayList<>();
        FastMealyMemState<O> fs = this.getInitialState();
        stateIDs.add(fs.getSID());
        for (I i : input) {
            fs = this.getSuccessor(fs, i);
            if(fs == null) return stateIDs;
            stateIDs.add(fs.getSID());
        }
        return stateIDs;
    }

    public QueryResponseMeta getMetaAtStateViaBase(FastMealyMemState<O> state, FastMealyMemState<O> base) {
        QueryResponseMeta qr = null;
        for(Word<I> metaInput : this.stateMetaDataMap.keySet()) {
            ArrayList<Integer> pathStates = getStateIDsOnPath(metaInput);
            if(pathStates.get(pathStates.size()-1) == state.getSID()) {
                if(pathStates.contains(base.getSID())) {
                    return this.stateMetaDataMap.get(metaInput).iterator().next();
                } else if (qr == null) {
                    qr = this.stateMetaDataMap.get(metaInput).iterator().next();
                }
            }
        }
        return qr;
    }

    public QueryResponseMeta getMetaAtStateWithInput(Word<I> query) {

        HashSet<QueryResponseMeta> metaInput = this.stateMetaDataMap.get(query);
        if (metaInput == null) 
            return null;

        for(QueryResponseMeta qm : this.stateMetaDataMap.get(query)) {
            if(Word.fromArray(qm.getInputs(), 0, qm.getInputs().length).equals(query))
                return qm;
        }
        return null;
    }

    public void addStateMetaDataMap(QueryResponseMeta stateMetaData) {
        Word<I> input = (Word<I>)Word.fromArray(stateMetaData.getInputs(), 0, stateMetaData.getInputs().length);
        this.stateMetaDataMap.computeIfAbsent(input, k-> new HashSet<QueryResponseMeta>()).add(stateMetaData);
    }

    // Instead of just counting the symbols in the query, this function calculates the size
    // of the first prefix that will refine the model.
    public int getQueryLength(Word<I> query) {
        int cnt = 0;
        FastMealyMemState<O> curr = this.getInitialState();
        for (int i = 0; i < query.size(); i++) {
            curr = this.getSuccessor(curr, query.getSymbol(i));
            cnt++;
            if (curr == null) {
                break;
            }
        }
        return cnt;
    }

	public void removeUndefinedStates() {
        HashSet<Integer> toKeep = new HashSet<>();
        HashSet<FastMealyMemState<O>> toRemove = new HashSet<>();
        for(FastMealyMemState<O> s : this.getStates()) {
            boolean defined = true;
            for(I i : this.getInputAlphabet()) {
                if(this.getSuccessor(s, i) == null) {
                    defined = false;
                    break;
                }
            }
            if(defined) {
                toKeep.add(s.getSID());
                for(I i : this.getInputAlphabet()) {
                    toKeep.add(this.getSuccessor(s, i).getSID());
                }
            }
        }
        for(FastMealyMemState<O> s : this.getStates()) {
            if(!toKeep.contains(s.getSID())) {
                toRemove.add(s);
            }
        }
        for(FastMealyMemState<O> s : toRemove) {
            this.removeStateAndMemory(s);
        }
	}
}
