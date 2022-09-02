package greyboxinterface;

import java.lang.ProcessBuilder.Redirect;
import java.util.ArrayList;
import java.util.Collections;
import java.util.logging.Logger;

import learner.Config;

public class TargetInterface {

	private static Logger log = Logger.getLogger(TargetInterface.class.getName());

    Config config;
    private Process targetProcess;
    private int cmdIndex = 0;
    private int launchTimes = -1;
    private long pid = -1;
    private boolean learnerControlledTarget = false;

    public TargetInterface(Config config) {
        this.config = config;
        if(config.launchCmds != null && !config.launchViaPtracer) learnerControlledTarget = true;
    }

    public void killTarget() throws Exception {
        if(!learnerControlledTarget) return;
        if(pid == -1) return;
        log.fine("Shutting down target at PID=" + String.valueOf(pid));
        Process p = Runtime.getRuntime().exec("kill -2 " + String.valueOf(pid));
        p.waitFor();
        Thread.sleep(200);
        this.pid = -1;
    }

    public boolean launchTarget(boolean force) throws Exception {
        if (!learnerControlledTarget) return false;
        if (!force) force = config.resetTargetEachQuery;

        // If we only have one launch command, and program is already running, don't relaunch
        if (pid != -1 && !force && config.launchCmds.size() < 2) return false;
        launchTimes++;
        if (!force && launchTimes % 2 != 0) return false;

        this.killTarget();
        ArrayList<String> cmd = new ArrayList<>();
        if (config.aslrDisable != null) {
            Collections.addAll(cmd, config.aslrDisable.split(" "));
        }
        Collections.addAll(cmd, config.launchCmds.get(cmdIndex % config.launchCmds.size()).split(" "));
        cmd.removeIf(c -> c.equals(""));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectError(Redirect.INHERIT);
        targetProcess = pb.start();
        pid = targetProcess.pid();
        Thread.sleep(config.ptraceDelay);
        cmdIndex++;
        return true;
    }

    public boolean isLearnerControlledTarget() {
        return learnerControlledTarget;
    }
}
