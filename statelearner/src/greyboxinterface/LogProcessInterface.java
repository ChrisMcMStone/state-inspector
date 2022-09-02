package greyboxinterface;

import java.lang.ProcessBuilder.Redirect;
import java.util.logging.Logger;

import learner.Config;

public class LogProcessInterface {

	private static Logger log = Logger.getLogger(PTraceInterface.class.getName());

    private String pythonCmd;
    private String execPath;
    private String outDir;
    private String appName;

    public LogProcessInterface(Config config) {
        this.pythonCmd = config.pythonCmd;
        this.execPath = config.logInterfacePath;
        this.outDir = config.outputDir;
        this.appName = config.appName;
    }

    public void processLogs(int sessionID, boolean zeroed) throws Exception {
        String cmd[] = buildCmd(sessionID, zeroed);
        log.fine("Launching logger: " + String.join(" ", cmd));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectError(Redirect.INHERIT);
        Process p = pb.start();
        p.waitFor();
    }

    private String[] buildCmd(int sessionID, boolean zeroed) {
        String cmd[] = {this.pythonCmd, this.execPath,
                        "--root", this.outDir,
                        "--ctrl", this.outDir + "/" + this.appName + sessionID + ".log",
                        "--dump", this.outDir + "/dump" + sessionID + ".log",
                        "--malloc", this.outDir + "/malloc" + sessionID + ".log",
                        "--out", this.outDir + "/" + Config.META_LOG_PREFIX + sessionID + ".log",
                        "--zeroed", zeroed ? "1" : "0"};
        return cmd;
    }
}
