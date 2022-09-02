package datastructures;

import java.util.ArrayList;

import org.javatuples.Triplet;

import net.automatalib.words.Word;

public class MergedState<I> {

    private ArrayList<AllocOffset> diffs;
    private Word<I> input;

    public MergedState() {
        this.diffs = new ArrayList<>();
    }

    public Word<I> getInput() {
        return input;
    }

    public void setInput(Word<I> input) {
        this.input = input;
    }

    public ArrayList<AllocOffset> getDiffs() {
        return diffs;
    }

    public void addDiff(AllocOffset diff) {
        this.diffs.add(diff);
    }
}
