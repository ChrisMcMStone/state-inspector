package datastructures;

import java.util.ArrayList;

import com.google.common.base.Optional;

import org.json.JSONArray;
import org.json.JSONObject;

public class TaintResult {
    private String logName;
    private Long pc;
    private Long watchpoint;
    private Long originalWatchpoint;
    private Boolean isStateful;
    private Optional<TaintExtendedResult> extendedResult;
    private Optional<DataInferenceResult> dataInference;

    public TaintResult(JSONObject ja) {
        logName = ja.getString("log_name");
        pc = ja.getLong("pc");
        watchpoint = ja.getLong("watchpoint");
        originalWatchpoint = ja.getLong("orig_watchpoint");
        isStateful = ja.getBoolean("stateful");
        extendedResult = TaintExtendedResult.of(ja.optJSONObject("extended"));
        dataInference = DataInferenceResult.of(ja.optJSONObject("data_inference"));
    }

    public static ArrayList<TaintResult> of(JSONArray ja) {
        ArrayList<TaintResult> trs = new ArrayList<>();
        ja.forEach(v -> trs.add(new TaintResult((JSONObject)v)));
        return trs;
    }

    public Long getOriginalWatchpoint() {
        return originalWatchpoint;
    }

    public Long getWatchpoint() {
        return watchpoint;
    }

    public Long getPc() {
        return pc;
    }

    public Optional<TaintExtendedResult> getExtendedResult() {
        return extendedResult;
    }

    public Boolean isStateMemory() {
        return isStateful;
    }

    public String getLogName() {
        return logName;
    }

    public void setLogName(String logName) {
        this.logName = logName;
    }
}
