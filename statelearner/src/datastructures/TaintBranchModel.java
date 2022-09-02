package datastructures;

import java.util.ArrayList;

import com.google.common.base.Optional;
import org.json.JSONArray;
import org.json.JSONObject;

public class TaintBranchModel {
    private ArrayList<TaintModelVariable> modelVariables;

    public TaintBranchModel(JSONArray ja) {
        modelVariables = new ArrayList<>();
        ja.forEach(v -> modelVariables.add(new TaintModelVariable((JSONObject)v)));
    }

    public ArrayList<TaintModelVariable> getModelVariables() {
        return modelVariables;
    }
}
