package greyboxinterface;

import java.lang.ProcessBuilder.Redirect;
import java.util.logging.Logger;
import java.util.ArrayList;
import java.util.Collections;

import learner.Config;

public class PTraceInterface {

    private static Logger log = Logger.getLogger(PTraceInterface.class.getName());

    private Config config;
    private String execPath;
    private String appName;
    private Process ptraceProcess;
    private long pid = -1;
    private long delay = 0;

    public PTraceInterface(Config config) {
        this.execPath = config.ptracePath;
        this.appName = config.appName;
        this.delay = config.ptraceDelay;
        this.config = config;
    }

    public void launchSnapshotter(int sessionID, String outputDir, TainterConfig taintConfig, boolean isZeroed) throws Exception {
        String baseCmd[] = taintConfig == null ? buildLaunchCmd(sessionID, outputDir, isZeroed) : buildTainterLaunchCmd(sessionID, outputDir, taintConfig, isZeroed);

        ArrayList<String> cmd = new ArrayList<>();
        if (isLearnerControlledTarget()) {
          if (config.aslrDisable != null) {
            Collections.addAll(cmd, config.aslrDisable.split(" "));
          }

          Collections.addAll(cmd, baseCmd);
          if (config.signalPtraceAttach) {
            cmd.add("-signal-attach");
          }

          cmd.add("--");
          Collections.addAll(cmd, config.launchCmds.get(0).split(" "));
          cmd.removeIf(c -> c.equals(""));
        } else {
          Collections.addAll(cmd, baseCmd);

          if (config.signalPtraceAttach) {
            cmd.add("-signal-attach");
          }
        }

        log.fine("Launching ptrace: " + String.join(" ", cmd));
        try {
            killSnapshotter();
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectError(Redirect.INHERIT);
            ptraceProcess = pb.start();
            pid = ptraceProcess.pid();
			Thread.sleep(delay);
        } catch (Exception e) {
            log.severe("Failed to launch Ptrace. ");
            throw e;
        }
    }

    public void deleteSessionSnapshots(int sessionID, String outputDir) throws Exception {
        String cmd[] = {"find", outputDir, "-name", "*sessID*", "-delete"};
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectError(Redirect.INHERIT);
        Process p = pb.start();
        p.waitFor();
    }

    public void killSnapshotter() throws Exception {
        if( pid == -1) return;
        log.fine("Shutting down ptrace at PID=" + String.valueOf(pid));
        Process p = Runtime.getRuntime().exec("kill -2 " + String.valueOf(pid));
        p.waitFor();
    }
    
    private String[] buildLaunchCmd(int sessionID, String outputDir, boolean isZeroed) {
        
        String launchCmd[] = { this.execPath, 
                               "-app", this.appName,
                               "-save-mappings", 
                               "-dump-dir", outputDir,
                               "-session-id", String.valueOf(sessionID),
                               "-trace-malloc", "malloc" + String.valueOf(sessionID) + ".log",
                               isZeroed ? "-malloc-zerod" : "-malloc-ffed"
        };

        return launchCmd;
    }

    private String[] buildTainterLaunchCmd(int sessionID, String outputDir, TainterConfig tainterConfig, boolean isZeroed) { 
        tainterConfig.sessionID = sessionID;

        String launchCmd[] = { this.execPath,
                               "-app", this.appName,
                               "-save-mappings",
                               "-dump-dir", outputDir,
                               "-session-id", String.valueOf(sessionID),
                               "-trace-malloc", "malloc" + String.valueOf(sessionID) + ".log",
                               "-watchpoint-malloc-trace", tainterConfig.reprLogFilename, 
                               "-watchpoint", String.valueOf(tainterConfig.wpAllocAddress), String.valueOf(tainterConfig.wpAllocSize), String.valueOf(tainterConfig.watchpointAddress()), String.valueOf(tainterConfig.wpSize),
                               "-watchpoint-dump-min", String.valueOf(tainterConfig.getMinWatchpointDumpID()),
                               "-watchpoint-dump-max", String.valueOf(tainterConfig.getMaxWatchpointDumpID()),
                               isZeroed ? "-malloc-zerod" : "-malloc-ffed"
        };

        return launchCmd;
    }

    public boolean isLearnerControlledTarget() {
        boolean is = config.launchViaPtracer && config.launchCmds != null && config.launchCmds.size() > 0;
        log.finer("tracer controlled target: " + is);
        return is;
    }
}
