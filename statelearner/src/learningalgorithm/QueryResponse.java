package learningalgorithm;

import java.util.ArrayList;

import net.automatalib.words.Word;

public class QueryResponse<I, O> {

    private ArrayList<QueryResponseMeta> qrs;
    private Word<I> inputWord;
    private Word<O> outputWord;
    private boolean isHappyFlow;
    private Integer sessionID;

    public QueryResponse(ArrayList<QueryResponseMeta> qrs, Word<I> inputWord, Word<O> outputWord, Integer sessionID) {
        this.qrs = qrs;
        this.outputWord = outputWord;
        this.inputWord = inputWord;
        this.isHappyFlow = false;
        this.sessionID = sessionID;
    }

    public ArrayList<QueryResponseMeta> getQrs() {
        return qrs;
    }

    public void setQrs(ArrayList<QueryResponseMeta> qrs) {
        this.qrs = qrs;
    }

    public Word<O> getOutputWord() {
        return outputWord;
    }

    public void setOutputWord(Word<O> outputWord) {
        this.outputWord = outputWord;
    }

    public Word<I> getInputWord() {
        return inputWord;
    }

    public void setInputWord(Word<I> inputWord) {
        this.inputWord = inputWord;
    }

    public void prefixMe(int len) {
        if (len >= this.inputWord.size()) return;
        this.inputWord = this.inputWord.prefix(len);
        this.outputWord = this.outputWord.prefix(len);
        int origSize = qrs.size();
        if (len >= origSize) return;
        for (int i = 0; i < (origSize-len); i++) {
            this.qrs.remove(qrs.size()-1);
        }
    }

    public boolean isHappyFlow() {
        return isHappyFlow;
    }

    public void setHappyFlow(boolean isHappyFlow) {
        this.isHappyFlow = isHappyFlow;
    }

    public Integer getSessionID() {
        return sessionID;
    }
}