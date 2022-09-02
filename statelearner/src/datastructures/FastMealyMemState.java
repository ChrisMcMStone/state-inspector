package datastructures;
import java.util.ArrayList;

import learningalgorithm.QueryResponseMeta;
import net.automatalib.automata.base.fast.AbstractFastState;
import net.automatalib.automata.transducers.impl.FastMealy;
import net.automatalib.automata.transducers.impl.MealyTransition;

/**
 * A state in a {@link FastMealy} automaton.
 *
 * @param <O> output symbol class.
 *
 * @author Malte Isberner
 */
public final class FastMealyMemState<O> extends AbstractFastState<MealyTransition<FastMealyMemState<O>, O>>{

    /**
     *
     */
    private static final long serialVersionUID = -3862233182869583490L;
    private boolean isBaseState;
    private int sid;

    public FastMealyMemState(int numInputs, int sid) {
        super(numInputs);
        this.sid = sid;
    }

    public int getSID() {
        return sid;
    }

    public static long getSerialversionuid() {
        return serialVersionUID;
    }

	public void setIsBaseState(boolean isBootstrap) {
        this.isBaseState = isBootstrap;
	}

    public boolean isBaseState() {
        return isBaseState;
    }

    @Override
    public String toString() {
        return "s" + sid;
    }
}
