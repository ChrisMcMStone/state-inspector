package learningalgorithm;

import datastructures.StateAddrSet;

public class StatsOracle {
    public int bootstrapCounter = 0;
    public int membershipCounter = 0;
    public int failedCounter = 0;
    public int watchpointCounter = 0;
    public int negativeTaintCounter = 0;
    public int postiveTaintCounter = 0;

    public int uniqueStateMemBytes = 0;
    public int uniqueStateMemAllocations = 0;
    public long startTime = 0;

    public StatsOracle(){
        this.startTime = System.currentTimeMillis();
    }

    public String formattedStats() {
        StringBuilder sb = new StringBuilder();

        sb.append("\n------------------ MEMORY STATS -----------------");
        sb.append("\n# Unique bytes for state classification:  " + uniqueStateMemBytes);
        sb.append("\n# Unique allocations containing bytes:    " + uniqueStateMemAllocations);
        sb.append("\n\n---------------- SUT QUERY STATS ----------------");
        sb.append("\n# Bootstrap queries:                      " + bootstrapCounter);
        sb.append("\n# Membership queries:                     " + membershipCounter);
        sb.append("\n# Watchpoint queries:                     " + watchpointCounter);
        sb.append("\n# Failed queries:                         " + failedCounter);
        sb.append("\n# Total queries (exc failed):             " + (bootstrapCounter + membershipCounter + watchpointCounter));
        sb.append("\n# Total time elapsed (hh:mm:ss):          " + getElapsedTimeString());
        sb.append("\n\n------------ TAINT ANALYSIS STATS ---------------");
        sb.append("\n# Total watchpoints hits analysed:        " + (negativeTaintCounter + postiveTaintCounter));
        sb.append("\n# Of which: positive state memory:        " + postiveTaintCounter);
        sb.append("\n#           negative state memory:        " + negativeTaintCounter);

        return sb.toString();
    }

	public void setMemoryStats(StateAddrSet as) {
        this.uniqueStateMemBytes = as.getMonitorAddrsMap().size();
        this.uniqueStateMemAllocations = as.getMonitorAddrsMap().keySet().size();
    }
    
    public long getElapsedLearningTimeMinutes() {
        return (System.currentTimeMillis() - this.startTime) / 60000;
    }

    public long getElapsedLearningTimeSeconds() {
        return (System.currentTimeMillis() - this.startTime) / 1000;
    }

    public String getElapsedTimeString() {
        long seconds = getElapsedLearningTimeSeconds();
        long p1 = seconds % 60;
        long p2 = seconds / 60;
        long p3 = p2 % 60;
        p2 = p2 / 60;
        return (p2 > 9 ? String.valueOf(p2) : "0" + p2) + ":" +
               (p3 > 9 ? String.valueOf(p3) : "0" + p3) + ":" + 
               (p1 > 9 ? String.valueOf(p1) : "0" + p1);
    }
}