package greyboxinterface;

import com.google.common.base.Optional;
import com.google.common.collect.Multimap;
import datastructures.AllocOffset;
import datastructures.MallocEntry;
import datastructures.MallocIncremental;
import datastructures.Snapshot;
import org.javatuples.Pair;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;

public class StateMemInterface {
    private MallocIncremental baseMallocs;

    public StateMemInterface(MallocIncremental mi) {
        this.baseMallocs = mi;
    }

    public HashMap<AllocOffset, Optional<byte[]>> run(Snapshot snapshot, ArrayList<MallocEntry> mallocLog, Long heapBase, Multimap<Pair<Long, Long>, Pair<Long, Long>> locs) throws Exception {

        ArrayList<Pair<AllocOffset, Long>> offsets = this.baseMallocs.getOffsets(mallocLog, snapshot.timestamp, heapBase, locs);
        RandomAccessFile f = new RandomAccessFile(String.valueOf(snapshot.path), "r");

        HashMap<AllocOffset, Optional<byte[]>> bytes = new HashMap<>();

        // offset = <<base addr, base size, alloc offset, size>, raw offset>
        for (Pair<AllocOffset, Long> offset : offsets) {
            int size = offset.getValue0().locSize.intValue();
            int off = offset.getValue1().intValue();
            if (off == -1) {
                // Add a mapping to null for state memory keys that we couldn't map
                bytes.put(offset.getValue0(), Optional.absent());
            } else {
                byte[] dst = new byte[size];
                for(int i=0; i<size;i++) {
                    f.seek(off+i);
                    dst[i] = (byte) f.readUnsignedByte();
                }

                bytes.put(offset.getValue0(), Optional.of(dst));
            }
        }

        f.close();
        return bytes;
    }

    public MallocIncremental getBaseMallocs() {
        return baseMallocs;
    }

    public void setBaseMallocs(MallocIncremental baseMallocs) {
        this.baseMallocs = baseMallocs;
    }
}
