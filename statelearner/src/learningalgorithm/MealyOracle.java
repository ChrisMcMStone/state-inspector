package learningalgorithm;

import java.io.FileReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import de.learnlib.api.exception.SULException;
import greyboxinterface.LogProcessInterface;
import greyboxinterface.PTraceInterface;
import greyboxinterface.TainterConfig;

import java.util.logging.Logger;

import learner.Config;
import learner.StateLearnerSUL;
import net.automatalib.words.Word;
import net.automatalib.words.WordBuilder;
import socket.SocketConfig;
import utils.Utils;

public class MealyOracle<I, O> {

	private static Logger log = Logger.getLogger(MealyOracle.class.getName());

	private final int MAX_RETRY = 2;
	private int curr_attempt = 0;
	StateLearnerSUL<I, O> sul;
	boolean use_cache = false;
	Config config;
	private int sessionID;
	private PTraceInterface ptrace;
	private LogProcessInterface lp;

	public MealyOracle(StateLearnerSUL<I, O> sul, PTraceInterface ptrace, LogProcessInterface lp, Config config) {
		this.sul = sul;
		this.ptrace = ptrace;
		this.lp = lp;
		this.config = config;
	}

	public QueryResponse<I, O> answerQuery(Word<I> input) throws Exception {
		return answerQuery(input, null, false, true);
	}

	public QueryResponse<I, O> answerQuery(Word<I> input, boolean is_zeroed) throws Exception {
		return answerQuery(input, null, false, is_zeroed);
	}

	public QueryResponse<I, O> answerQuery(Word<I> input, TainterConfig tainterConfig) throws Exception {
		if (config instanceof SocketConfig)
			return answerQuery(input, ((SocketConfig) config).combine_query, tainterConfig, false, true);
		else
			return answerQuery(input, false, tainterConfig, false, true);
	}

	public QueryResponse<I, O> answerQuery(Word<I> input, TainterConfig tainterConfig, boolean is_retry, boolean is_zeroed) throws Exception {
		if (config instanceof SocketConfig)
			return answerQuery(input, ((SocketConfig) config).combine_query, tainterConfig, is_retry, is_zeroed);
		else
			return answerQuery(input, false, tainterConfig, is_retry, is_zeroed);
	}

	public QueryResponse<I, O> answerQuery(Word<I> query, boolean combine_query, TainterConfig tainterConfig, boolean is_retry, boolean is_zeroed)
			throws Exception {

		if(!is_retry) this.curr_attempt = 0;

		this.incrementSessionID();
		ptrace.launchSnapshotter(this.getSessionID(), config.outputDir, tainterConfig, is_zeroed);

		this.sul.pre();
		int outputSize = 0;
		Word<O> output = null;
		if (combine_query) {
			output = sul.stepWord(query);
			if (output.toString().contains(Config.SUT_NEEDS_RESTART)) {
				throw new SULException(new Throwable("Harness indicated SUT needs restarting"));
			}
			outputSize = output.size();
		} else {
			WordBuilder<O> outputBuilder = new WordBuilder<>(query.length());
			for (I sym : query) {
				outputSize++;
				O res = this.sul.step(sym);
				if (res.toString().equals(Config.SUT_NEEDS_RESTART)) {
					throw new SULException(new Throwable("Harness indicated SUT needs restarting"));
				}
				outputBuilder.add(res);
				if(Utils.isDisabled(res.toString(), config.disableOutputs)) break;
			}
			output = outputBuilder.toWord();
		}

		String disabledSuffix = "";
		if(outputSize < query.size()) {
			for(int i =0 ; i<query.size()-outputSize; i++) disabledSuffix = disabledSuffix + " -";
		}
		//if (tainterConfig == null)
		log.info("Q:" + this.getSessionID() + " [" + query + " | " + output.toString() + disabledSuffix + "]");

		sul.post();
		ptrace.killSnapshotter();
		try {
			lp.processLogs(this.getSessionID(), is_zeroed);
		} catch (Exception e) {
			log.severe("Failed to launch logger.py.");
			throw e;
		}

		ArrayList<QueryResponseMeta> response = new ArrayList<>();

		String metaFile = config.outputDir + "/" + Config.META_LOG_PREFIX + this.getSessionID() + ".log";

		log.fine("Parse QueryResponseMeta for file: " + metaFile);

		try (Reader reader = new FileReader(metaFile)) {

			// Convert JSON File to Java Object
			// Staff staff = gson.fromJson(reader, Staff.class);
			Gson gson = new Gson();
			JsonArray ja = JsonParser.parseReader(reader).getAsJsonArray();
			if (ja.size() < 1) throw new Exception();

			// This enforces that we use the snapshots in the meta log corresponding to the
			// right number of
			// inputs and outputs (since we snapshot on both reads and writes)
			for (int j = 0; j < outputSize; j++) {
				for (JsonElement e : ja) {
					QueryResponseMeta qr = gson.fromJson(e, QueryResponseMeta.class);
					String[] x = query.prefix(j + 1).stream().toArray(String[]::new);
					String[] y = output.prefix(j + 1).stream().toArray(String[]::new);
					if (Arrays.equals(qr.getInputs(), query.prefix(j + 1).stream().toArray(String[]::new)) && Arrays
							.equals(qr.getOutputs(), output.prefix(j + 1).stream().toArray(String[]::new))) {
						response.add(qr);
						break;
					}
				}
			}
		} catch (Exception e) {
				if (this.curr_attempt >= MAX_RETRY) throw new SULException(new Throwable("Max re-attempts of failed query exceeded."));
				log.severe("Unpopulated logs caused logger.py to fail in processing them, retrying query...");
				Thread.sleep(1000);
				this.curr_attempt++;
				return answerQuery(query, tainterConfig, true, is_zeroed);
		}

		return new QueryResponse<I, O>(response, query, output, this.sessionID);
	}

	public int getSessionID() {
		return this.sessionID;
	}

	public void incrementSessionID() {
		this.sessionID++;
		this.sul.updateSessionID(this.sessionID);
	}

	public void cleanup() throws Exception {
		if(config.deleteSnapshots) ptrace.deleteSessionSnapshots(this.sessionID, config.outputDir);
	}

	public void setUp() {
		this.sul.setUp();
	}

	public void toggleSlowReset() throws Exception {
		this.sul.toggleSlowReset();
	}

}