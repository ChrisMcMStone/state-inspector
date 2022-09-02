package bootstrapstrategies;

import java.util.ArrayList;

import learningalgorithm.QueryResponse;
import utils.Flow;
import utils.Utils;

public class HappyFlow<I, O> implements BootstrapFlowStrategy<I,O> {

    private ArrayList<Flow<I, O>> happyFlows;
    private ArrayList<String> disabledOuputs;

    public HappyFlow(ArrayList<Flow<I, O>> happyFlows, ArrayList<String> disabledOutputs) {
        this.happyFlows = happyFlows;
        this.disabledOuputs = disabledOutputs;
    }

    @Override
    public ArrayList<Flow<I,O>> generateBootstrapFlows() {
        for (Flow<I, O> happyFlow : this.happyFlows) {
            // set happy flow property
            happyFlow.setIsHappyFlow();
        }
        return this.happyFlows;
    }

    @Override
    public void flowCleanup(QueryResponse<I,O> qrs) {
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
    public boolean isPermitted(QueryResponse<I,O> qrs, Flow<I,O> testedFlow) {
        return true;
    }
}