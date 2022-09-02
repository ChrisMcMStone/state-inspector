package datastructures;

import java.util.ArrayList;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;

public class MallocEntry {

    public Long timestamp;
    public Long size;
    public Long pc;
    public Long addr;

    public MallocEntry(Long timestamp, Long size, Long pc, Long addr) {
        this.timestamp = timestamp;
        this.size = size;
        this.pc = pc;
        this.addr = addr;
    }

    public static ArrayList<MallocEntry> buildMallocEntryList(Path logPath) throws IOException {

        BufferedReader reader = Files.newBufferedReader(logPath);
        return reader.lines()
                .filter(line -> line.split(" ", 3)[1].equals("M") && line.trim().split(" ").length == 5)
                .map(line -> {
                    // E.g.: 1576088900537 M 0x7fffffffc978 0x18 0x555555a0e070
                    String[] parts = line.trim().split(" ");
                    //if (parts.length != 5) {
                    //    throw new IllegalArgumentException(line);
                    //}
                    long timestamp = Long.decode(parts[0]);
                    long pc = Long.decode(parts[2]);
                    long size = Long.decode(parts[3]);
                    long addr = Long.decode(parts[4]);

                    return new MallocEntry(timestamp, size, pc, addr);
                }).collect(Collectors.toCollection(ArrayList::new));
    }

    @Override
    public boolean equals(Object obj) {
        if(!(obj instanceof MallocEntry)) return false;
        MallocEntry objCmp = (MallocEntry) obj;
        return objCmp.timestamp.equals(this.timestamp) && objCmp.size.equals(this.size) 
               && objCmp.pc.equals(this.pc) && objCmp.addr.equals(this.addr);
    }
}
