package bootstrapstrategies;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import learningalgorithm.QueryResponse;
import net.automatalib.words.Word;
import net.automatalib.words.impl.SimpleAlphabet;
import utils.Flow;
import utils.Utils;

public class HappyFlowMutated<I, O> implements BootstrapFlowStrategy<I, O> {

    private ArrayList<Flow<I, O>> happyFlows;
    private HashSet<Flow<I, O>> enabledFlows;
    private SimpleAlphabet<I> alphabet;
    private int maxRepeatedInputsNo;
    private ArrayList<String> disabledOuputs;
    private HashMap<Word<I>, HashSet<O>> observedOutputs;

    public HappyFlowMutated(ArrayList<Flow<I, O>> happyFlows, SimpleAlphabet<I> inputs, int maxRepeatedInputsNo,
            ArrayList<String> disabledOutputs) {
        this.happyFlows = happyFlows;
        this.maxRepeatedInputsNo = maxRepeatedInputsNo;
        this.alphabet = inputs;
        this.disabledOuputs = disabledOutputs;
        this.observedOutputs = new HashMap<>();
        this.enabledFlows = new HashSet<>();
    }

    @Override
    public ArrayList<Flow<I, O>> generateBootstrapFlows() {

        ArrayList<Flow<I, O>> flows = new ArrayList<>();

        for (Flow<I, O> happyFlow : this.happyFlows) {
            // Add happyflow first
            happyFlow.setIsHappyFlow();
            flows.add(happyFlow);

            ArrayList<I> hfInputs = happyFlow.getInputs();
            // Assume each I/O in happy flow is a new state
            for (int i = 0; i < hfInputs.size()-1; i++) {
                ArrayList<I> prefix = i + 1 <= hfInputs.size() ? new ArrayList<>(hfInputs.subList(0, i + 1)) : hfInputs;

                for (I input : alphabet) {
                    ArrayList<I> flowInputs = new ArrayList<>();
                    flowInputs.addAll(prefix);
                    for (int j = 0; j < maxRepeatedInputsNo; j++) {
                        flowInputs.add(input);
                    }
                    flows.add(new Flow<I, O>(flowInputs));
                }
            }
        }

        return flows;
    }
    @Override
    public void flowCleanup(QueryResponse<I, O> qrs) {
        // First check if error state is reached and if so trim query up until that point
        for (int k = 0; k < qrs.getOutputWord().size(); k++) {
            O outSymb = qrs.getOutputWord().getSymbol(k);
            if (Utils.isDisabled(outSymb.toString(), this.disabledOuputs)) {
                // trim the query to exclude inputs after error/disabled state
                // (we don't want to missclassify memory which is allocated after a disable state)
                qrs.prefixMe(k + 1);
                break;
            }
        }
    }


    @Override
    public boolean isPermitted(QueryResponse<I, O> qrs, Flow<I, O> testedFlow) {

        boolean newObservation = false;

        if(enabledFlows.contains(testedFlow))
            return true;

        if (testedFlow.isHappyFlow()) {
            for (int k = 0; k < qrs.getOutputWord().size() - 1; k++) {
                Word<I> prefix = k + 1 < qrs.getOutputWord().size() ? qrs.getInputWord().subWord(0, k + 1)
                        : qrs.getInputWord();
                HashSet<O> outs = null;

                if (observedOutputs.containsKey(prefix)) {
                    outs = observedOutputs.get(prefix);
                } else {
                    outs = new HashSet<>();
                }
                // For the given happy flow state, the output corresponding to next input (hence
                // k+1)
                outs.add(qrs.getOutputWord().getSymbol(k + 1));
                observedOutputs.put(prefix, outs);
            }
            enabledFlows.add(testedFlow);
            return true;
        } else {
            // Filter out queries which have a happy base state prefix, but don't result in
            // error states or newly observed outputs from that state
            for (int k = 0; k < qrs.getOutputWord().size(); k++) {
                O outSymb = qrs.getOutputWord().getSymbol(k);

                //If we've reached error state, return true
                if(Utils.isDisabled(outSymb.toString(), this.disabledOuputs)) return true;

                Word<I> prefix = k+1 < qrs.getOutputWord().size() ? qrs.getInputWord().subWord(0, k + 1)
                        : qrs.getInputWord();
                HashSet<O> outs = null;

                if (observedOutputs.containsKey(prefix)) {
                    outs = observedOutputs.get(prefix);
                } else {
                    continue;
                }

                newObservation = outs.add(outSymb) ? true : false || newObservation;
                observedOutputs.put(prefix, outs);
            }
            if(newObservation)
                enabledFlows.add(testedFlow);
            return newObservation;
        }
    }
}