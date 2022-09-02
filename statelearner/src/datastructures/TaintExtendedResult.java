package datastructures;

import com.google.common.base.Optional;

import org.json.JSONArray;
import org.json.JSONObject;

public class TaintExtendedResult {
    private TaintBranchModel branchModelTaken;
    private TaintBranchModel branchModelNotTaken;
    private Optional<TaintBranchAnalysis> branchTaken;
    private Optional<TaintBranchAnalysis> branchNotTaken;

    public TaintExtendedResult(JSONObject ja) {
        branchModelTaken = new TaintBranchModel(ja.getJSONArray("branch_model_taken"));
        branchModelNotTaken = new TaintBranchModel(ja.getJSONArray("branch_model_taken"));
        branchTaken = TaintBranchAnalysis.of(ja.optJSONObject("branch_taken"));
        branchNotTaken = TaintBranchAnalysis.of(ja.optJSONObject("branch_not_taken"));
    }

    public static Optional<TaintExtendedResult> of(JSONObject ja) {
        if (ja == null) {
            return Optional.absent();
        } else {
            return Optional.of(new TaintExtendedResult(ja));
        }
    }

	public TaintBranchModel getBranchModelTaken() {
		return branchModelTaken;
	}

	public TaintBranchModel getBranchModelNotTaken() {
		return branchModelNotTaken;
	}

	public Optional<TaintBranchAnalysis> getBranchTaken() {
		return branchTaken;
	}
	public Optional<TaintBranchAnalysis> getBranchNotTaken() {
		return branchNotTaken;
	}
}
