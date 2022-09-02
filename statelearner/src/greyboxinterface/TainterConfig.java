package greyboxinterface;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.javatuples.Pair;
import org.json.JSONException;
import org.json.JSONObject;

import datastructures.AllocOffset;
import datastructures.TaintResult;
import datastructures.WatchpointDump;

public class TainterConfig {
    public Long wpAllocAddress;
    public Long wpAllocOffset;
    public Long wpAllocSize;
    public Long wpSize;
    public int sessionID;
    public String reprLogFilename;
    public String input;
    public int minWatchpointDumpID;
    public int maxWatchpointDumpID;
    public ArrayList<Pair<String, WatchpointDump>> wpHits;
    public ArrayList<TaintResult> wpResults;

    private static Logger log = Logger.getLogger(TainterConfig.class.getName());

    public TainterConfig(Long wpAllocAddress, Long wpAllocSize, Long wpAllocOffset, Long wpSize, String reprLogFilename,
            String input, int minWatchpointDumpID, int maxWatchpointDumpID) {
        this.wpAllocAddress = wpAllocAddress;
        this.wpAllocOffset = wpAllocOffset;
        this.wpAllocSize = wpAllocSize;
        this.wpSize = wpSize;
        this.wpHits = new ArrayList<>();
        this.wpResults = new ArrayList<>();
        this.input = input;
        this.reprLogFilename = reprLogFilename;
        this.minWatchpointDumpID = minWatchpointDumpID;
        this.maxWatchpointDumpID = maxWatchpointDumpID;
    }

    public void setSessionID(int id) {
        this.sessionID = id;
    }

    public Long watchpointAddress() {
        return wpAllocAddress + wpAllocOffset;
    }

    public void addWatchpointHit(String wpHit) throws JSONException, IOException {
        wpHits.add(new Pair<>(wpHit, new WatchpointDump(
                                new JSONObject(
                                    new String(Files.readAllBytes(Paths.get(wpHit)))))));
    }

    public void addWatchpointResult(TaintResult wpResult) {
        wpResults.add(wpResult);
    }

    public ArrayList<TaintResult> getWatchpointResults() {
        return this.wpResults;
    }

    public Boolean isStateMemory() {
        return wpResults.stream().reduce(
            false,
            (_acc, v) -> v.isStateMemory(),
            Boolean::logicalOr
        );
    }

    public AllocOffset getAddr() {
        return new AllocOffset(this.wpAllocAddress, this.wpAllocSize, this.wpAllocOffset, this.wpSize);
    }

    public int getMinWatchpointDumpID() {
        return minWatchpointDumpID;
    }

    public int getMaxWatchpointDumpID() {
        return maxWatchpointDumpID;
    }

    public void processHitLogs(String watchpointLogFileDirectory) throws JSONException, IOException {
        FilenameFilter metaFilter = (dir, name) -> name.contains("sessID-" + this.sessionID + "-watchpoint")
                && name.contains(".log");
        File f = new File(watchpointLogFileDirectory);
        List<String> paths = Arrays.asList(f.listFiles(metaFilter)).stream().map(p -> p.getAbsolutePath())
                .collect(Collectors.toList());
        Collections.sort(paths);
        for (String path : paths) {
            this.addWatchpointHit(path);
        }
    }

    public ArrayList<Pair<String, WatchpointDump>> getWpHits() {
        return wpHits;
    }

    //Remove hits at selection of given PC values
	public void removeHits(HashSet<Long> stateWatchpointHitPCS) {
        for(Long pc : stateWatchpointHitPCS) {
            this.wpHits.removeIf(v -> v.getValue1().getPc().equals(pc));
        }
	}

	public void addTaintResultIfMatch(TaintResult r) {
        for(Pair<String, WatchpointDump> hit : this.getWpHits()) {
            if(hit.getValue0().equals(r.getLogName())) this.addWatchpointResult(r);
        }
	}

    public String getInput() {
        return input;
    }

    public List<String> getInputList() {
        return Arrays.asList(this.input.split(" "));
    }

    public void setInput(String input) {
        this.input = input;
    }
}
