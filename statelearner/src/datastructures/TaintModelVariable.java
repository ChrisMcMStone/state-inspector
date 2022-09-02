package datastructures;

import com.google.common.base.Optional;

import org.json.JSONArray;
import org.json.JSONObject;

public class TaintModelVariable {
    private Long address;
    private Long size;
    private Long value;

    public TaintModelVariable(JSONObject ja) {
        address = ja.getLong("address");
        size = ja.getLong("size");
        value = ja.getLong("value");
    }

    public Long getAddress() {
        return address;
    }

    public Long getSize() {
        return size;
    }

    public Long getValue() {
        return value;
    }
}
