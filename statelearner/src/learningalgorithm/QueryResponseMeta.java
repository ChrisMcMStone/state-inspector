package learningalgorithm;

public class QueryResponseMeta {

    private String dump_file;
    private String[] inputs;
    private String[] outputs;
    private String type;
    private int count;
    private long timestamp;
    private String malloc_log;

    public String getDump_file() {
        return dump_file;
    }

    public void setDump_file(String dump_file) {
        this.dump_file = dump_file;
    }

    public String[] getInputs() {
        return inputs;
    }

    public void setInputs(String[] inputs) {
        this.inputs = inputs;
    }

    public String[] getOutputs() {
        return outputs;
    }

    public void setOutputs(String[] outputs) {
        this.outputs = outputs;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getMalloc_log() {
        return malloc_log;
    }

    public void setMalloc_log(String malloc_log) {
        this.malloc_log = malloc_log;
    }

}