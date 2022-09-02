package greyboxinterface;

import java.io.BufferedReader;
import java.io.File;
import java.io.FilenameFilter;
import java.io.InputStreamReader;
import java.lang.ProcessBuilder.Redirect;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import datastructures.StateAddrSet;
import learner.Config;

public class StateDiffInterface {

    private Config config;
    private static String STATE_MEM_LOG = "stateaddrset.log";
    private static Logger log = Logger.getLogger(StateDiffInterface.class.getName());
    private static FilenameFilter metaFilter = 
                (dir, name) -> name.contains(Config.META_LOG_PREFIX) && name.endsWith(".log");

    public StateDiffInterface(Config config) {
        this.config = config;
    }

    public StateAddrSet getStateMemory(String mallocLog, int sessionID, List<Integer> includedFlows) throws Exception {
        List<String> cmd = buildCmd(mallocLog, sessionID, includedFlows);
        log.info("Diff tool launch command: " + String.join(" ", cmd));
        String jsonAddrSet = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectError(Redirect.INHERIT);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            jsonAddrSet = reader.readLine();
            if (jsonAddrSet != null) {
                return new StateAddrSet(jsonAddrSet);
            } else {
                return null;
            }
        } catch (Exception e) {
            log.severe("diff_tool.py fail: " + e.getMessage());
            throw e;
        }
    }

    private List<String> buildCmd(String mallocLog, int sessionID, List<Integer> includedFlows) {

        // Get all the meta log files (can't use wildcards)

        File f = new File(config.outputDir);
        List<String> paths = Arrays.asList(f.listFiles(metaFilter)).stream().map( p -> p.getAbsolutePath() ).collect(Collectors.toList());
         
        List<String> cmd = new ArrayList<String>();
        cmd.add(config.pythonCmd); cmd.add(config.difftoolPath);
        cmd.add("--mem-maps"); cmd.add(config.outputDir + "/" + Config.MAPS_LOG_PREFIX + sessionID + ".log");
        cmd.add("--mlog-filter"); cmd.add(config.outputDir + "/" + (mallocLog));
        cmd.add("--json");
        cmd.add("--apply-hueristics");
        cmd.add("--output-log"); cmd.add(config.outputDir + "/" + STATE_MEM_LOG);
        cmd.add("--calc-confidence");
        if(config.disableOutputs.size() > 0) {
            cmd.add("--terminating-outputs");
            for (String out : config.disableOutputs) {
                cmd.add(out);
            }
        }
        cmd.add("--logs");
        int logCnt = 0;
        for (String path : paths) {
            //Only include logs from specified sessionIDs
            if(includedFlows.stream().anyMatch(sessID -> path.contains("_"+sessID+".log"))) {
                cmd.add(path);
                logCnt++;
            }
        }
        log.info(logCnt + " meta logs passed to diff tool");
        return cmd;
	}

}
