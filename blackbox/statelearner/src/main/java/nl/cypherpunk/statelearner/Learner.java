/*
 *  Copyright (c) 2016 Joeri de Ruiter
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package nl.cypherpunk.statelearner;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Random;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.FileAppender;
import org.slf4j.LoggerFactory;

import de.learnlib.acex.analyzers.AcexAnalyzers;
import de.learnlib.algorithms.dhc.mealy.MealyDHC;
import de.learnlib.algorithms.kv.mealy.KearnsVaziraniMealy;
import de.learnlib.algorithms.lstar.mealy.ExtensibleLStarMealyBuilder;
import de.learnlib.algorithms.malerpnueli.MalerPnueliMealy;
import de.learnlib.algorithms.rivestschapire.RivestSchapireMealy;
import de.learnlib.algorithms.ttt.mealy.TTTLearnerMealyBuilder;
import de.learnlib.api.algorithm.LearningAlgorithm;
import de.learnlib.api.logging.LearnLogger;
import de.learnlib.api.oracle.EquivalenceOracle;
import de.learnlib.api.query.DefaultQuery;
import de.learnlib.filter.cache.mealy.MealyCacheOracle;
import de.learnlib.filter.statistic.Counter;
import de.learnlib.filter.statistic.oracle.MealyCounterOracle;
import de.learnlib.oracle.equivalence.MealyRandomWordsEQOracle;
import de.learnlib.oracle.equivalence.MealyWMethodEQOracle;
import de.learnlib.oracle.equivalence.MealyWpMethodEQOracle;
import de.learnlib.oracle.membership.SULOracle;
import de.learnlib.util.statistics.SimpleProfiler;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.incremental.ConflictException;
import net.automatalib.serialization.dot.GraphDOT;
import net.automatalib.words.Word;
import net.automatalib.words.impl.ListAlphabet;
import nl.cypherpunk.statelearner.LogOracle.MealyLogOracle;
import nl.cypherpunk.statelearner.ModifiedWMethodEQOracle.MealyModifiedWMethodEQOracle;
import nl.cypherpunk.statelearner.socket.SocketConfig;
import nl.cypherpunk.statelearner.socket.SocketSUL;
import nl.cypherpunk.statelearner.tls.TLSConfig;
import nl.cypherpunk.statelearner.tls.TLSSUL;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class Learner {
	LearningConfig config;
	boolean combine_query = false;
	ListAlphabet<String> alphabet;
	StateLearnerSUL<String, String> sul;
	SULOracle<String, String> memOracle;
	MealyLogOracle<String, String> logMemOracle;
	MealyCounterOracle<String, String> statsMemOracle;
	MealyCacheOracle<String, String> cachedMemOracle;
	MealyCounterOracle<String, String> statsCachedMemOracle;
	LearningAlgorithm<MealyMachine<?, String, ?, String>, String, Word<String>> learningAlgorithm;

	SULOracle<String, String> eqOracle;
	MealyLogOracle<String, String> logEqOracle;
	MealyCounterOracle<String, String> statsEqOracle;
	MealyCacheOracle<String, String> cachedEqOracle;
	MealyCounterOracle<String, String> statsCachedEqOracle;
	EquivalenceOracle<MealyMachine<?, String, ?, String>, String, Word<String>> equivalenceAlgorithm;

	public Learner(LearningConfig config) throws Exception {
		this.config = config;

		// Create output directory if it doesn't exist
		Path path = Paths.get(config.output_dir);
		if (Files.notExists(path)) {
			Files.createDirectories(path);
		}

		configureLogging(config.output_dir);

		LearnLogger log = LearnLogger.getLogger(Learner.class.getSimpleName());

		if (config.type == LearningConfig.TYPE_SOCKET) {
			log.info("Using socket SUL");

			// Create the socket SUL
			SocketConfig socketConfig = new SocketConfig(config);
			sul = new SocketSUL(socketConfig);
			combine_query = socketConfig.getCombineQuery();
			alphabet = ((SocketSUL) sul).getAlphabet();
		} else if (config.type == LearningConfig.TYPE_TLS) {
			log.info("Using TLS SUL");

			// Create the TLS SUL
			sul = new TLSSUL(new TLSConfig(config));
			alphabet = ((TLSSUL) sul).getAlphabet();
		}

		loadLearningAlgorithm(config.learning_algorithm, alphabet, sul);
		loadEquivalenceAlgorithm(config.eqtest, alphabet, sul);
	}

	public void loadLearningAlgorithm(String algorithm, ListAlphabet<String> alphabet,
			StateLearnerSUL<String, String> sul) throws Exception {
		// Create the membership oracle
		// memOracle = new SULOracle<String, String>(sul);
		// Add a logging oracle
		logMemOracle = new MealyLogOracle<String, String>(sul, LearnLogger.getLogger("learning_queries"),
				combine_query);
		// Count the number of queries actually sent to the SUL
		statsMemOracle = new MealyCounterOracle<String, String>(logMemOracle, "membership queries to SUL");
		// Use cache oracle to prevent double queries to the SUL
		cachedMemOracle = MealyCacheOracle.createDAGCacheOracle(alphabet, statsMemOracle);
		// Count the number of queries to the cache
		statsCachedMemOracle = new MealyCounterOracle<String, String>(cachedMemOracle, "membership queries to cache");

		// Instantiate the selected learning algorithm
		switch (algorithm.toLowerCase()) {
			case "lstar":
				learningAlgorithm = new ExtensibleLStarMealyBuilder<String, String>().withAlphabet(alphabet)
						.withOracle(statsCachedMemOracle).create();
				break;

			case "dhc":
				learningAlgorithm = new MealyDHC<String, String>(alphabet, statsCachedMemOracle);
				break;

			case "kv":
				learningAlgorithm = new KearnsVaziraniMealy<String, String>(alphabet, statsCachedMemOracle, true,
						AcexAnalyzers.BINARY_SEARCH_FWD);
				break;

			case "ttt":
				learningAlgorithm = new TTTLearnerMealyBuilder<String, String>()
						.withAlphabet(alphabet).withOracle(statsCachedMemOracle)
						.withAnalyzer(AcexAnalyzers.BINARY_SEARCH_FWD).create();
				break;
				
			case "mp":
				learningAlgorithm = new MalerPnueliMealy<String, String>(alphabet, statsCachedMemOracle);
				break;
				
			case "rs":
				learningAlgorithm = new RivestSchapireMealy<String, String>(alphabet, statsCachedMemOracle);
				break;

			default:
				throw new Exception("Unknown learning algorithm " + config.learning_algorithm);
		}		
	}
	
	public void loadEquivalenceAlgorithm(String algorithm, ListAlphabet<String> alphabet, StateLearnerSUL<String, String> sul) throws Exception {
		//TODO We could combine the two cached oracle to save some queries to the SUL
		// Create the equivalence oracle
		//eqOracle = new SULOracle<String, String>(sul);
		// Add a logging oracle
		logEqOracle = new MealyLogOracle<String, String>(sul, LearnLogger.getLogger("equivalence_queries"), combine_query);
		// Add an oracle that counts the number of queries
		statsEqOracle = new MealyCounterOracle<String, String>(logEqOracle, "equivalence queries to SUL");
		// Use cache oracle to prevent double queries to the SUL
		cachedEqOracle = MealyCacheOracle.createDAGCacheOracle(alphabet, statsEqOracle);
        // Count the number of queries to the cache
		statsCachedEqOracle = new MealyCounterOracle<String, String>(cachedEqOracle, "equivalence queries to cache");
		
		// Instantiate the selected equivalence algorithm
		switch(algorithm.toLowerCase()) {
			case "wmethod":
				equivalenceAlgorithm = new MealyWMethodEQOracle<String, String>(statsCachedEqOracle, config.max_depth);
				break;

			case "modifiedwmethod":
				equivalenceAlgorithm = new MealyModifiedWMethodEQOracle<String, String>(config.max_depth, statsCachedEqOracle);
				break;
				
			case "wpmethod":
				equivalenceAlgorithm = new MealyWpMethodEQOracle<String, String>(statsCachedEqOracle, config.max_depth);
				break;
				
			case "randomwords":
				equivalenceAlgorithm = new MealyRandomWordsEQOracle<String, String>(statsCachedEqOracle, config.min_length, config.max_length, config.nr_queries, new Random(config.seed));
				break;
				
			default:
				throw new Exception("Unknown equivalence algorithm " + config.eqtest);
		}	
	}
	
	public void learn() throws IOException, InterruptedException {
		LearnLogger log = LearnLogger.getLogger(Learner.class.getSimpleName());

		log.info("Using learning algorithm " + learningAlgorithm.getClass().getSimpleName());
		log.info("Using equivalence algorithm " + equivalenceAlgorithm.getClass().getSimpleName());
		
		log.info("Starting learning");
		
		SimpleProfiler.start("Total time");
		
		boolean learning = true;
		Counter round = new Counter("Rounds", "");

		round.increment();
		log.logPhase("Starting round " + round.getCount());
		SimpleProfiler.start("Learning");
		learningAlgorithm.startLearning();
		SimpleProfiler.stop("Learning");

		MealyMachine<?, String, ?, String> hypothesis = learningAlgorithm.getHypothesisModel();
		
		while(learning) {
			// Write outputs
			writeDotModel(hypothesis, alphabet, config.output_dir + "/hypothesis_" + round.getCount() + ".dot");

			// Search counter-example
			DefaultQuery<String, Word<String>> counterExample = null;
			while(learning) {
				try {
					SimpleProfiler.start("Searching for counter-example");
					counterExample = equivalenceAlgorithm.findCounterExample(hypothesis, alphabet);	
					SimpleProfiler.stop("Searching for counter-example");
				} catch (ConflictException e) {
					log.error("Detetected non-determinism, dropping counter-example");
					continue;
				}
				break;
			}
			
			if(counterExample == null) {
				// No counter-example found, so done learning
				learning = false;
				
				// Write outputs
				writeDotModel(hypothesis, alphabet, config.output_dir + "/learnedModel.dot");
				//writeAutModel(hypothesis, alphabet, config.output_dir + "/learnedModel.aut");
			}
			else {
				// Counter example found, update hypothesis and continue learning
				log.logCounterexample("Counter-example found: " + counterExample.toString());
				//TODO Add more logging
				round.increment();
				log.logPhase("Starting round " + round.getCount());
				
				SimpleProfiler.start("Learning");
				learningAlgorithm.refineHypothesis(counterExample);
				SimpleProfiler.stop("Learning");
                log.info(statsMemOracle.getStatisticalData().getSummary());
                log.info(statsCachedMemOracle.getStatisticalData().getSummary());
                log.info(statsEqOracle.getStatisticalData().getSummary());
                log.info(statsCachedEqOracle.getStatisticalData().getSummary());
				
				hypothesis = learningAlgorithm.getHypothesisModel();
			}
		}

		SimpleProfiler.stop("Total time");
		
		// Output statistics
		log.info("-------------------------------------------------------");
		log.info(SimpleProfiler.getResults());
		log.info(round.getSummary());
		log.info(statsMemOracle.getStatisticalData().getSummary());
		log.info(statsCachedMemOracle.getStatisticalData().getSummary());
		log.info(statsEqOracle.getStatisticalData().getSummary());
		log.info(statsCachedEqOracle.getStatisticalData().getSummary());
		log.info("States in final hypothesis: " + hypothesis.size());		
	}
	
	public static void writeAutModel(MealyMachine<?, String, ?, String> model, ListAlphabet<String> alphabet, String filename) throws FileNotFoundException {
		// Make use of LearnLib's internal representation of states as integers
		@SuppressWarnings("unchecked")
		MealyMachine<Integer, String, ?, String> tmpModel = (MealyMachine<Integer, String, ?, String>) model;
		
		// Write output to aut-file
		File autFile = new File(filename);
		PrintStream psAutFile = new PrintStream(autFile);
		
		int nrStates = model.getStates().size();
		// Compute number of transitions, assuming the graph is complete
		int nrTransitions = nrStates * alphabet.size();
		
		psAutFile.println("des(" + model.getInitialState().toString() + "," + nrTransitions + "," + nrStates + ")");
		
		Collection<Integer> states = tmpModel.getStates();

		for(Integer state: states) {
			for(String input: alphabet) {
				String output = tmpModel.getOutput(state, input);
				Integer successor = tmpModel.getSuccessor(state, input);
				psAutFile.println("(" + state + ",'" + input + " / " + output + "', " + successor + ")");
			}
		}
		
		psAutFile.close();
	}
	
	public static void writeDotModel(MealyMachine<?, String, ?, String> model, ListAlphabet<String> alphabet, String filename) throws IOException, InterruptedException {
		// Write output to dot-file
		File dotFile = new File(filename);
		PrintStream psDotFile = new PrintStream(dotFile);
		GraphDOT.write(model, alphabet, psDotFile);
		psDotFile.close();
		
		//TODO Check if dot is available
		
		// Convert .dot to .pdf
		Runtime.getRuntime().exec("dot -Tpdf -O " + filename);
	}
	
	public void configureLogging(String output_dir) throws SecurityException, IOException {
		final Logger logbackLogger = (Logger) LoggerFactory.getLogger("learning_queries");
		//logbackLogger.addAppender(buildAppender(output_dir + "/learning_queries.log"));
		logbackLogger.addAppender(buildAppenderConsole(output_dir + "/learning_queries.log"));

		final Logger logbackLogger2 = (Logger) LoggerFactory.getLogger(Learner.class.getSimpleName());
		logbackLogger2.addAppender(buildAppender(output_dir + "/learner.log"));
		logbackLogger2.addAppender(buildAppenderConsole(output_dir + "/learner.log"));
	}

	  private ConsoleAppender<ILoggingEvent> buildAppenderConsole(String fileName) {
        final LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();

        final PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setContext(context);
		encoder.setPattern("%date %level %logger{10} %msg%n");
		encoder.start();
		
		//Create a new FileAppender
		ConsoleAppender<ILoggingEvent> file = new ConsoleAppender<ILoggingEvent>();
		//file.setName("FileLogger");
		file.setEncoder(encoder);
		file.setContext(context);
		file.start();

        return file;
    }

	  private FileAppender<ILoggingEvent> buildAppender(String fileName) {
        final LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();

        final PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setContext(context);
		encoder.setPattern("%date %level %logger{10} %msg%n");
		encoder.start();
		
		//Create a new FileAppender
		FileAppender<ILoggingEvent> file = new FileAppender<ILoggingEvent>();
		file.setFile(fileName);
		file.setEncoder(encoder);
		file.setContext(context);
		file.setAppend(true);
		file.start();

        return file;
    }
	
	public static void main(String[] args) throws Exception {
		if(args.length < 1) {
			System.err.println("Invalid number of parameters");
			System.exit(-1);
		}
		
		LearningConfig config = new LearningConfig(args[0]);
	
		Learner learner = new Learner(config);
		learner.learn();
	}
}
