package learner;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.logging.Logger;

import bootstrapstrategies.BootstrapFlowStrategy;
import bootstrapstrategies.HappyFlow;
import bootstrapstrategies.HappyFlowMutated;
import datastructures.FastMealyMemModel;
import greyboxinterface.LogProcessInterface;
import greyboxinterface.PTraceInterface;
import greyboxinterface.StateDiffInterface;
import greyboxinterface.TargetInterface;
import learningalgorithm.CoreLearner;
import learningalgorithm.MealyOracle;
import learningalgorithm.StatsOracle;
import net.automatalib.automata.transducers.impl.compact.CompactMealy;
import net.automatalib.words.impl.SimpleAlphabet;
import socket.SocketConfig;
import socket.SocketSUL;
import tls.TLSConfig;
import tls.TLSSUL;
import utils.Utils;

public class MemStateLearner {

	private static Logger log;
	static {
		System.setProperty("java.util.logging.config.file",
              "src/logging.properties");
	   	log = Logger.getLogger(MemStateLearner.class.getName());
	}

	private Config config;
	private StateLearnerSUL<String, String> sul;
	private CoreLearner<String, String> coreLearner;
	private FastMealyMemModel<String, String> model;
	private SimpleAlphabet<String> alphabet;
	private PTraceInterface ptrace;
	private BootstrapFlowStrategy<String, String> boostrapFlowGenerator;
	private LogProcessInterface logTool;
	private StateDiffInterface diffTool;
	private TargetInterface target;
	private MealyOracle<String, String> oracle;
	private long rendererPID=-1;
	private StatsOracle stats;

	public MemStateLearner(Config config) throws Exception {
		this.config = config;

		this.ptrace = new PTraceInterface(config);
		this.logTool = new LogProcessInterface(config);
		this.diffTool = new StateDiffInterface(config);

		// Check the type of learning we want to do and create corresponding
		// configuration and SUL
		if (config.type == Config.TYPE_SOCKET) {
			log.info("Using socket SUL");

			// Create the socket SUL
			sul = new SocketSUL(new SocketConfig(config));
			alphabet = ((SocketSUL) sul).getAlphabet();
		} else if (config.type == Config.TYPE_TLS) {
			log.info("Using TLS SUL");

			// Create the TLS SUL
			sul = new TLSSUL(new TLSConfig(config));
			alphabet = ((TLSSUL) sul).getAlphabet();
		}
		config.setAlphabet(alphabet);
        Process p = Runtime.getRuntime().exec("rm -rf " + config.outputDir);
        p.waitFor();
        p = Runtime.getRuntime().exec("sudo -u " + System.getProperty("user.name") + " mkdir " + config.outputDir);
        p.waitFor();

		this.oracle = new MealyOracle<String, String>(sul, ptrace, logTool, config);
		this.model = new FastMealyMemModel<>(config.getAlphabet());
		this.target = new TargetInterface(config);
                if (!target.isLearnerControlledTarget()) {
                  log.finer("setting up SUL via oracle; not learner controlled");
                  oracle.setUp();
                }
		this.stats = new StatsOracle();
		this.coreLearner = new CoreLearner<String, String>(oracle, stats, target, diffTool, model, config);

		if(config.bootstrapMode == Config.supportedBootstrapModes.HAPPYFLOW) {
			this.boostrapFlowGenerator = new HappyFlow<String,String>(config.bootstrapFlows, config.disableOutputs);
		} else if (config.bootstrapMode == Config.supportedBootstrapModes.HAPPYFLOWMUTATED
					|| config.bootstrapMode == Config.supportedBootstrapModes.HAPPYFLOWMUTATEDSLOW) {
			this.boostrapFlowGenerator = new HappyFlowMutated<String, String>(config.bootstrapFlows, 
										alphabet, config.MAX_BOOTSTRAP_INPUT_ATTEMPTS, config.disableOutputs);
		}
	}

	public void learn() throws Exception {
		if(config.incModelDrawing) {
            ProcessBuilder pb = new ProcessBuilder(new String[]{"node", config.rendererPath, config.outputDir});
            rendererPID = pb.start().pid();
		}
		try {
			log.info("Bootstrap phase with " + config.numBootstrapRuns + " iterations of each flow.");
			coreLearner.bootstrap(this.boostrapFlowGenerator, config.numBootstrapRuns);
			Utils.drawModel(config, model, "bootstrap-model.dot", true);
			coreLearner.learn();
			Utils.drawModel(config, model, "full-model.dot", true);
			log.info("Learning completed successfully - pre-minimised model has " + this.model.size() + " states.");
			CompactMealy<String,String> minimisedModel = model.minimise();
			Utils.drawModel(config, minimisedModel, "test.dot", false);  //Final render for the web app
			Utils.drawModel(config, minimisedModel, "minimised-model.dot", true);
			log.info("Learning completed successfully - minimised model has " + minimisedModel.size() + " states.");
			model.printMemMap(config.getOutputDir() + "/mem-classifications.dump");
			log.info(stats.formattedStats());
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			log.severe(sw.toString());
		} finally {
			cleanup();
		}
	}

	public void cleanup() throws Exception {
		try {
			if(rendererPID != -1) {
				Process p = Runtime.getRuntime().exec("kill -2 " + String.valueOf(this.rendererPID));
				p.waitFor();
			}
		} catch (Exception e2) {
		} finally {
			target.killTarget();
			ptrace.killSnapshotter();
		}
	}

	public static void main(String[] args) throws Exception {
		if (args.length != 1) {
			log.severe("Invalid number of parameters");
			System.exit(-1);
		}
		Config config = new Config(args[0]);
		MemStateLearner memStateLearner = new MemStateLearner(config);

		memStateLearner.learn();

		Runtime.getRuntime().addShutdownHook(new Thread() {
        public void run() {
            try {
                Thread.sleep(100);
				System.out.println("Shutting down ...");
				memStateLearner.cleanup();

            } catch (Exception e) {
                Thread.currentThread().interrupt();
                e.printStackTrace();
            }
        }
    });
	}
}
