package bootstrapstrategies;

import java.util.ArrayList;

import learningalgorithm.QueryResponse;
import utils.Flow;

public interface BootstrapFlowStrategy<I,O> {

    public ArrayList<Flow<I, O>> generateBootstrapFlows();

    public void flowCleanup(QueryResponse<I, O> qrs);

    public boolean isPermitted(QueryResponse<I, O> qrs, Flow<I,O> testedFlow);
}