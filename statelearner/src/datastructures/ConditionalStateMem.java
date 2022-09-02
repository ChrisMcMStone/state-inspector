package datastructures;

public class ConditionalStateMem {
    
    private boolean conditionsMet;
    private boolean isStateMemory;

    public ConditionalStateMem(boolean conditionsMet, boolean isStateMemory) {
        this.conditionsMet = conditionsMet;
        this.isStateMemory = isStateMemory;
    }

    public boolean isConditionsMet() {
        return conditionsMet;
    }

    public void setConditionsMet(boolean conditionsMet) {
        this.conditionsMet = conditionsMet;
    }

    public boolean isStateMemory() {
        return isStateMemory;
    }

    public void setStateMemory(boolean isStateMemory) {
        this.isStateMemory = isStateMemory;
    }
}