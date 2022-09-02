package nl.cypherpunk.statelearner;


import de.learnlib.api.SUL;
import net.automatalib.words.Word;
import net.automatalib.words.WordBuilder;

public interface StateLearnerSUL<I, O> extends SUL<I, O> {
	default Word<O> stepWord(Word<I> in) throws de.learnlib.api.exception.SULException {
		WordBuilder<O> wbOutput = new WordBuilder<>(in.length());
		
		for(I sym: in) {
			wbOutput.add(step(sym));
		}
		
		return wbOutput.toWord();
	}
}
