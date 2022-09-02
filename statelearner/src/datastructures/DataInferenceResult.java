package datastructures;

import java.util.HashMap;

import com.google.common.base.Optional;
import org.json.JSONObject;

public class DataInferenceResult {
    private HashMap<Long, Long> addressToSize;

    public DataInferenceResult(JSONObject ja) {
        addressToSize = new HashMap<>();
        ja.keySet().forEach(addrStr -> addressToSize.put(Long.valueOf(addrStr), ja.getLong(addrStr)));
    }

    public static Optional<DataInferenceResult> of(JSONObject ja) {
        if (ja == null) {
            return Optional.absent();
        } else {
            return Optional.of(new DataInferenceResult(ja));
        }
    }

    public HashMap<Long, Long> getInference() {
        return addressToSize;
    }
}
