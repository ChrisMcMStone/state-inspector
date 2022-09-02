package greyboxinterface;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.ProcessBuilder.Redirect;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.Base64;
import org.javatuples.Pair;
import org.json.JSONArray;
import org.json.JSONTokener;

import datastructures.AllocOffset;
import datastructures.TaintResult;
import datastructures.WatchpointDump;
import learner.Config;

public class TainterInterface {

    private static Logger log = Logger.getLogger(TainterInterface.class.getName());
    private String pythonCmd;
    private String execPath;
    private String binaryPath;
    private ArrayList<String> extraBinaries;
    private String idaPath;
    private long insnWindow;
    private boolean extendedAnalysis;
    private String logRoot;
    private int maxWatchHits;
    private int a2lPrintRange;

    public TainterInterface(Config config) {
        this.pythonCmd = config.pythonCmd;
        this.execPath = config.tainterPath;
        this.binaryPath = config.binPath;
        this.extraBinaries = config.extraBinaries;
        this.idaPath = config.idaPath;
        this.insnWindow = config.tainterInsnWindow;
        this.logRoot = config.outputDir;
        this.maxWatchHits = config.maxWatchHitsPerAddr;
        this.a2lPrintRange = config.a2lPrintRange;
    }

    public void runTainter(List<TainterConfig> watchpoints, Set<AllocOffset> assumedMem, String reprLog, byte[] expValue, boolean conditionalSelfWrites)
            throws Exception {
        File stateMemFile = File.createTempFile("stateMem", ".log");
        BufferedWriter bufw = new BufferedWriter(new FileWriter(stateMemFile));
        for (AllocOffset alloc : assumedMem) {
            bufw.write(alloc.allocBaseAddress + " " + alloc.allocSize + 
                       " " + alloc.locOffset + " " + alloc.locSize);
            bufw.newLine();
        }
        bufw.close();

        ProcessBuilder cmd = buildLaunchCmd(watchpoints, reprLog, stateMemFile.getAbsolutePath(), expValue, conditionalSelfWrites);
        cmd.redirectError(Redirect.INHERIT);
        Process p = cmd.start();
        p.waitFor();

        /*
            * { "watchpoint": Long, "dependency": { "load_address": Long, "branch_address":
            * Long, "branch_target": Long, "branch_taken": Bool, }, "single_incoming":
            * Bool, "extended_check": Bool, "full_check": Bool, }
            */

        JSONTokener jsonParser = new JSONTokener(p.getInputStream());
        for (TaintResult r : TaintResult.of(new JSONArray(jsonParser))) {
            for (TainterConfig tc : watchpoints) {
                tc.addTaintResultIfMatch(r);
            }
        }
    }

    private ProcessBuilder buildLaunchCmd(List<TainterConfig> watchpoints, String reprLog, String assumedMemLog, byte[] expValue, boolean conditionalSelfWrites)
            throws IOException {
        List<String> cmdLine = new LinkedList<>();

        cmdLine.add("sudo");
        cmdLine.add("-u");
        cmdLine.add(System.getProperty("user.name"));
        cmdLine.add(pythonCmd);
        cmdLine.add(execPath);
        cmdLine.add("--binaries");
        cmdLine.add(binaryPath);
        for (String binary : extraBinaries) {
            cmdLine.add(binary);
        }
        cmdLine.add("--ida");
        cmdLine.add(idaPath);
        cmdLine.add("--window");
        cmdLine.add(Long.toString(insnWindow));

        //cmdLine.add("--data-tracker");

        if(conditionalSelfWrites)
            cmdLine.add("--self-write");

        cmdLine.add("--extended");
        cmdLine.add(assumedMemLog);
        cmdLine.add("--repr-mallocs");
        cmdLine.add(reprLog);
        cmdLine.add("--exp-val");
        cmdLine.add(new String(Base64.getEncoder().encode(expValue)));

        assert (watchpoints.size() > 0);
        cmdLine.add("--watchpoints");

        for (TainterConfig w : watchpoints) {
            for (Pair<String, WatchpointDump> pathDump : w.getWpHits()) {
                String path = pathDump.getValue0();
                String wpPrefix = path.replaceAll("\\.log$", "");
                cmdLine.add(wpPrefix);
            }
        }

        log.info(String.join(" ", cmdLine));
        return new ProcessBuilder(cmdLine);
    }

    public void runAddr2lineHit(TainterConfig w) {
        for (Pair<String, WatchpointDump> pathDump : w.getWpHits()) {
            String path = pathDump.getValue0();
            log.info("Displaying watchpoint hits made processing final input of query: " + w.input);
            try {
                addr2line(path);
            } catch (Exception e) {
                log.info("Addr2line failed for: " + path);
            }
        }
    }

    public void runAddr2lineResults(List<TainterConfig> watchpoints) {
        for (TainterConfig w : watchpoints) {
            for (TaintResult tr : w.getWatchpointResults()) {
                try{
                    if(tr.isStateMemory() && tr.getExtendedResult().isPresent()) {
                        if(tr.getExtendedResult().get().getBranchNotTaken().isPresent() &&
                            tr.getExtendedResult().get().getBranchNotTaken().get().getStorePC() != null) {
                            log.info("Printing source code details of conditional write due to taint tested memory");
                            addr2line(tr.getLogName(), tr.getExtendedResult().get().getBranchNotTaken().get().getStorePC());
                        }
                        if(tr.getExtendedResult().get().getBranchTaken().isPresent() &&
                            tr.getExtendedResult().get().getBranchTaken().get().getStorePC() != null) {
                            log.info("Printing source code details of conditional write due to taint tested memory");
                            addr2line(tr.getLogName(), tr.getExtendedResult().get().getBranchTaken().get().getStorePC());
                        }
                    }
                } catch (Exception e) {
                    log.info("Addr2line failed on conditional write address");
                }
            }
        }
    }

    private void addr2line(String watchpointLog) throws Exception {
        addr2line(watchpointLog, null);
    }
    private void addr2line(String watchpointLog, Long pc) throws Exception {
        boolean isHitResult = pc != null;

		try (Reader reader = new FileReader(watchpointLog)) {

			// Convert JSON File to Java Object
			// Staff staff = gson.fromJson(reader, Staff.class);
            JsonObject ja = JsonParser.parseReader(reader).getAsJsonObject();
            Long orig_address = ja.get("orig_address").getAsLong();
            if(!isHitResult) pc = ja.get("pc").getAsLong();
            JsonArray segments = ja.getAsJsonArray("segments");
            for (JsonElement ob : segments) {
                if(pc > ob.getAsJsonObject().get("low").getAsLong() && pc < ob.getAsJsonObject().get("high").getAsLong()) {
                    Long lookupAddr = pc - ob.getAsJsonObject().get("low").getAsLong();
                    String binPath = ob.getAsJsonObject().get("name").getAsString();
                    List<String> cmdLine = new LinkedList<>();
                    cmdLine.add("addr2line");
                    cmdLine.add("-f");
                    cmdLine.add("-e");
                    cmdLine.add(binPath);
                    cmdLine.add("0x"+Long.toHexString(lookupAddr));

                    if(!isHitResult) log.info("0x"+Long.toHexString(orig_address) + " watchpoint hit at 0x" + Long.toHexString(pc) + " in " + watchpointLog);

                    ProcessBuilder cmd = new ProcessBuilder(cmdLine);
                    cmd.redirectError(Redirect.INHERIT);
                    Process p = cmd.start();
                    p.waitFor();

                    BufferedReader a2lReader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    if(a2lReader.ready()) {
                        StringBuilder sb = new StringBuilder();

                        // 1st line is func name, so print to sysout
                        String funcName = a2lReader.readLine();
                        if (funcName.contains("?")) {
                            sb.append("Addr2line failed to find watchpoint hit's enclosing function.");
                        } else {
                            sb.append("Hit in function: " + funcName);
                        }

                        // 2nd line is source code file
                        String sourceLine = a2lReader.readLine();
                        if (sourceLine.contains("?")) {
                            sb.append("\nAddr2line failed to find source code line for given watchpoint hit.");
                        } else {
                            sb.append("\nAt source code file/line: " + sourceLine + "\nPreview:");
                            int sep = sourceLine.indexOf(':');
                            String sFile = sourceLine.substring(0, sep);
                            int lineNo = Integer.parseInt(sourceLine.substring(sep+1, sourceLine.length()));
                            FileInputStream fs= new FileInputStream(sFile);
                            BufferedReader br = new BufferedReader(new InputStreamReader(fs));

                            for(int i = 0; i < lineNo + this.a2lPrintRange; ++i) {
                                String src = br.readLine();
                                if (src == null) break;
                                if (i > (lineNo - this.a2lPrintRange)) {
                                    if(i == lineNo) {
                                        sb.append("\n*******HIT MARKER******");
                                    }
                                    sb.append("\n" + src);
                                }
                            }
                            br.close();
                        }
                        log.info(sb.toString());
                    }
                    return;
                }
            }
        }
    }
}
