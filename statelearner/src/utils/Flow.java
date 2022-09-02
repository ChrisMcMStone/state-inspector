package utils;

import java.util.ArrayList;
import java.util.Objects;

import net.automatalib.words.Word;

public class Flow<I, O> {

    private ArrayList<I> inputs = null;
    private ArrayList<O> outputs = null;
    private boolean isHappyFlow = false;
    
    public Flow (ArrayList<I> inputs, ArrayList<O> outputs) {
        this.inputs = inputs;
        this.outputs = outputs;
    }

    public Flow () {
        this.inputs = new ArrayList<>();
        this.outputs = new ArrayList<>();
    }

    public Flow (ArrayList<I> inputs) {
        this.inputs = inputs;
    }

    public ArrayList<I> getInputs() {
        return inputs;
    }

    public void setInputs(ArrayList<I> input) {
        this.inputs = input;
    }

    public void setInputs(Word<I> input) {
        this.inputs.clear();
        for (I i : input) {
            this.inputs.add(i);
        }
    }

    public ArrayList<O> getOutputs() {
        return outputs;
    }

    public void setOutputs(ArrayList<O> output) {
        this.outputs = output;
    }

    public int size() {
        return inputs.size();
    }

    public void setIsHappyFlow() {
        this.isHappyFlow = true;
    }

    public boolean isHappyFlow() {
        return this.isHappyFlow;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof Flow)) return false;
        Flow<I,O> c = (Flow<I,O>) obj;
        return (c.getInputs().equals(this.inputs) && c.getOutputs().equals(this.outputs));
    }

    @Override
    public int hashCode() {
        return Objects.hash(inputs, outputs);
    }
}