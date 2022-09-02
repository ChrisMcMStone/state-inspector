package datastructures;

import com.google.common.base.Optional;

import org.json.JSONObject;

public class TaintBranchAnalysis {
    private Boolean preMerge;
    private TaintBranchModel model;
    private Long storeAddress;
    private Long storeSize;
    private Long storePC;

    public TaintBranchAnalysis(JSONObject ja) {
        preMerge = ja.getBoolean("pre_merge");
        model = new TaintBranchModel(ja.getJSONArray("model"));
        storeAddress = ja.getLong("store_address");
        storeSize = ja.getLong("store_size");
        storePC = ja.getLong("store_pc");
    }

    public static Optional<TaintBranchAnalysis> of(JSONObject ja) {
        if (ja == null) {
            return Optional.absent();
        } else {
            return Optional.of(new TaintBranchAnalysis(ja));
        }
    }

    public Boolean getPreMerge() {
        return preMerge;
    }

    public TaintBranchModel getModel() {
        return model;
    }

    public Long getStoreAddress() {
        return storeAddress;
    }

    public Long getStoreSize() {
        return storeSize;
    }

    public Long getStorePC() {
        return storePC;
    }
}
