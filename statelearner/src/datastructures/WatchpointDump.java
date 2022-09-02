package datastructures;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

import org.json.JSONObject;

public class WatchpointDump {

    private Long address;
    private Long orig_address;
    private Long pc;
    private byte[] wp_value;

    public WatchpointDump(JSONObject jo) throws UnsupportedEncodingException {
        this.address = jo.getLong("address");
        this.orig_address = jo.getLong("orig_address");
        this.pc = jo.getLong("pc");
        String base64_wp_value = jo.getString("wp_value");
        this.wp_value = Base64.getDecoder().decode(base64_wp_value.getBytes("UTF-8"));
    }

    public Long getAddress() {
        return address;
    }

    public void setAddress(Long address) {
        this.address = address;
    }

    public Long getOrig_address() {
        return orig_address;
    }

    public void setOrig_address(Long orig_address) {
        this.orig_address = orig_address;
    }

    public Long getPc() {
        return pc;
    }

    public void setPc(Long pc) {
        this.pc = pc;
    }

    public byte[] getWp_value() {
        return wp_value;
    }

    public void setWp_value(byte[] wp_value) {
        this.wp_value = wp_value;
    }
}
