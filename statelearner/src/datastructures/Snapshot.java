package datastructures;

import java.nio.file.Path;

public class Snapshot {
    public enum Type {
        READ,
        WRITE,
    };

    public int id;
    public Path path;
    public long timestamp;
    public Type type;

    public Snapshot(long timestamp, Path path, Type type, int id) {
        this.timestamp = timestamp;
        this.path = path;
        this.type = type;
        this.id = id;
    }
}
