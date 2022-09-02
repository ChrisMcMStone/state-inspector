package learner;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.lang3.StringUtils;

import net.automatalib.words.impl.SimpleAlphabet;
import utils.Flow;

public class Config {

	protected Properties properties;
	public SimpleAlphabet<String> alphabet;

	static int TYPE_SOCKET = 1;
	static int TYPE_TLS = 2;

    public static final String DEFAULT_PYTHON = "python3";
    public String pythonCmd;

	public int type = TYPE_TLS;

	public String outputDir;

	private String projRoot;
	public String appName;
	public String binPath;
	public ArrayList<String> extraBinaries;
	public String difftoolPath;
	public String ptracePath;
	public String logInterfacePath;
	public boolean enableTainting = false;

    public boolean a2l;
    public int a2lPrintRange;

	public boolean incModelDrawing = false;
	public String modelCleanerPath;
	public String rendererPath;

	public final static String META_LOG_PREFIX = "meta_";
	public final static String MAPS_LOG_PREFIX = "mem_maps";
	public final static String DISABLE_OUTPUT = "-";

	public String idaPath;

	// tainter configuration
	public String tainterPath;
	public long tainterInsnWindow;
	public int maxWatchHitsPerAddr;

	// statemem configuration
	public String snapshotPath;
	public boolean deleteSnapshots = false;

	public static enum supportedBootstrapModes {
		HAPPYFLOW,
		HAPPYFLOWSLOW,
		HAPPYFLOWMUTATED,
		HAPPYFLOWMUTATEDSLOW
	}
	public supportedBootstrapModes bootstrapMode = supportedBootstrapModes.HAPPYFLOW;
	public ArrayList<Flow<String, String>> bootstrapFlows;
	public int numBootstrapRuns = 3;
	public int MAX_BOOTSTRAP_INPUT_ATTEMPTS = 5;
	public ArrayList<String> disableOutputs;
	public ArrayList<String> resetInputs;
	public ArrayList<String> emptyOutputs;
	public static String SUT_NEEDS_RESTART = "RESET_FAIL";
	public int ioEquivalenceDepth = 1;

	public boolean negativeConditionalMemory = false;
	public boolean extraTaintCheck = false;
	public int explorationBound = 0;
	public int timeBound = 0;
	public int ptraceDelay = 500;
	public boolean memoryInitAlternate = false;
	public boolean resetTargetEachQuery = false;

	// target launch cmds
	public ArrayList<String> launchCmds;
	public String aslrDisable;

        // ptrace launch
        public boolean launchViaPtracer = false;
        public boolean signalPtraceAttach = false;

	public Config(String filename) throws Exception {
		properties = new Properties();

		InputStream input = new FileInputStream(filename);
		properties.load(input);

		loadProperties();
	}

	public Config(Config config) throws Exception {
		properties = config.getProperties();
		loadProperties();
	}

	public void loadProperties() throws Exception {
		if (properties.getProperty("base_path") != null) {
			projRoot = properties.getProperty("base_path");
			if (projRoot.charAt(projRoot.length()-1) != '/') projRoot = projRoot + '/';
		} else {
			throw new Exception("ERROR: Specify project root directory in config.");
		}

		if (properties.getProperty("num_bootstrap_runs") != null)
			numBootstrapRuns = Integer.valueOf(properties.getProperty("num_bootstrap_runs"));

		if (properties.getProperty("output_dir") != null) {
			outputDir = properties.getProperty("output_dir");
		} else {
			throw new Exception("ERROR: Need to specify output_dir in config.");
		}

		if (properties.getProperty("app_name") != null) {
			appName = properties.getProperty("app_name");
		} else {
			throw new Exception("ERROR: Need to specify app_name parameter for ptrace syscall hooking activation.");
		}

		if (properties.getProperty("bin_path") != null) {
			binPath = properties.getProperty("bin_path");
		} else {
			throw new Exception("ERROR: Need to specify bin_path: directory containing target binary.");
		}

		if (properties.getProperty("extra_binaries") != null) {
			extraBinaries = new ArrayList<String>(Arrays.asList(properties.getProperty("extra_binaries").split(":")));
		} else {
			extraBinaries = new ArrayList<String>();
		}

		if (properties.getProperty("difftool_path") != null) {
			difftoolPath = this.projRoot + properties.getProperty("difftool_path");
		} else {
			throw new Exception("ERROR: Need to specify difftool_path in config.");
		}

		if (properties.getProperty("enable_taint_analysis") != null) {
			if(properties.getProperty("enable_taint_analysis").equals("true")){
				enableTainting = true;
			};
		}

		if (properties.getProperty("negative_conditional_memory") != null) {
			if(properties.getProperty("negative_conditional_memory").equals("true")){
				negativeConditionalMemory = true;
			};
		}

		if (properties.getProperty("extra_taint_check") != null) {
			if(properties.getProperty("extra_taint_check").equals("true")){
				extraTaintCheck = true;
			};
		}

		if (properties.getProperty("print_watchpoint_hit_source_info") != null) {
			if(properties.getProperty("print_watchpoint_hit_source_info").equals("true")){
				a2l = true;
			};
		}

		if (properties.getProperty("delete_snapshots_after_use") != null) {
			if(properties.getProperty("delete_snapshots_after_use").equals("true")){
				deleteSnapshots = true;
			};
		}

		if (properties.getProperty("memory_init_alternate") != null) {
			if(properties.getProperty("memory_init_alternate").equals("true")){
				memoryInitAlternate = true;
			};
		}

		if (properties.getProperty("reset_target_each_query") != null) {
			if(properties.getProperty("reset_target_each_query").equals("true")){
				resetTargetEachQuery = true;
			};
		}

		if (properties.getProperty("bootstrap_mode") != null) {
			bootstrapMode = supportedBootstrapModes.valueOf(properties.getProperty("bootstrap_mode"));
		} 
		
		if (properties.getProperty("mutated_bootstrap_per_input_max_repeat") != null) {
			MAX_BOOTSTRAP_INPUT_ATTEMPTS = Integer.parseInt(properties.getProperty("mutated_bootstrap_per_input_max_repeat"));
		}

		if (properties.getProperty("watchpoint_source_code_print_range") != null) {
			a2lPrintRange = Integer.parseInt(properties.getProperty("watchpoint_source_code_print_range"));
		} else {
		    a2lPrintRange = 5;
		}

		if (properties.getProperty("inc_model_drawing") != null) {
			if(properties.getProperty("inc_model_drawing").equals("true")){
				incModelDrawing = true;
			};
		}

		if (properties.getProperty("model_cleaner") != null) {
			modelCleanerPath = this.projRoot + properties.getProperty("model_cleaner");
		} else {
			incModelDrawing = false;
		}

		if (properties.getProperty("renderer_path") != null) {
			rendererPath = this.projRoot + properties.getProperty("renderer_path");
		} else {
			rendererPath = this.projRoot + "js_model_renderer/app.js";
		}

		if (properties.getProperty("ptrace_path") != null) {
			ptracePath = this.projRoot + properties.getProperty("ptrace_path");
		} else {
			throw new Exception("ERROR: Need to specify ptrace_path: the file path for ptrace-statemem binary.");
		}

		if (properties.getProperty("log_interface_path") != null) {
			logInterfacePath = this.projRoot + properties.getProperty("log_interface_path");
		} else {
			throw new Exception("ERROR: Need to specify log_interface_path: the file path for python log processer.");
		}

		if (properties.getProperty("type") != null) {
			if (properties.getProperty("type").equalsIgnoreCase("socket"))
				type = TYPE_SOCKET;
			else if (properties.getProperty("type").equalsIgnoreCase("tls"))
				type = TYPE_TLS;
		}
		if (properties.getProperty("bootstrap_flows") != null)
			parseFlows(properties.getProperty("bootstrap_flows"));

		if (properties.getProperty("ida_path") != null) {
			idaPath = properties.getProperty("ida_path");
		} else {
			throw new Exception("ERROR: Need to specify ida_path: an absolute path to IDA Pro.");
		}

		if (properties.getProperty("tainter_path") != null) {
			tainterPath = this.projRoot + properties.getProperty("tainter_path");
		} else {
			throw new Exception("ERROR: Need to specify tainter_path: path to the tainter.");
		}

		if (properties.getProperty("tainter_insn_window") != null) {
			tainterInsnWindow = Long.parseUnsignedLong(properties.getProperty("tainter_insn_window"));
		} else {
		    tainterInsnWindow = 512L;
		}

		if (properties.getProperty("io_equivalence_merge_depth") != null) {
			ioEquivalenceDepth = Integer.parseInt(properties.getProperty("io_equivalence_merge_depth"));
		} 

		if (( properties.getProperty("exploration_bound") != null && properties.getProperty("time_bound") != null) ||
		(properties.getProperty("exploration_bound") == null && properties.getProperty("time_bound") == null) ) {
			throw new Exception("Must specify either an exploration_bound OR time_bound in the configuration.");
		}

		if (properties.getProperty("exploration_bound") != null) {
			explorationBound = Integer.parseInt(properties.getProperty("exploration_bound"));
			if(explorationBound < 1) throw new Exception("exploration_bound must be greater than zero.");
		} 

		if (properties.getProperty("time_bound") != null) {
			timeBound = Integer.parseInt(properties.getProperty("time_bound"));
		} 

		if (properties.getProperty("ptrace_attach_delay") != null) {
			ptraceDelay = Integer.parseInt(properties.getProperty("ptrace_attach_delay"));
		} 

		if (properties.getProperty("max_watch_hits_per_addr") != null) {
			maxWatchHitsPerAddr = Integer.parseInt(properties.getProperty("max_watch_hits_per_addr"));
		} else {
		    maxWatchHitsPerAddr = 100;
		}

		if (properties.getProperty("disable_outputs") != null) {
			this.disableOutputs = new ArrayList<String>(Arrays.asList(properties.getProperty("disable_outputs").split(" ")));
		}

		if (properties.getProperty("reset_inputs") != null) {
			this.resetInputs = new ArrayList<String>(Arrays.asList(properties.getProperty("reset_inputs").split(" ")));
		}

		if (properties.getProperty("empty_outputs") != null) {
			this.emptyOutputs = new ArrayList<String>(Arrays.asList(properties.getProperty("empty_outputs").split(" ")));
		} else {
			throw new Exception("Must specifiy empty_outputs in configuration - the outputs from the test harness which indicated no response");
		}

		if (properties.getProperty("target_launch_cmds") != null) {
			parseLaunchCmds(properties.getProperty("target_launch_cmds"));
		} else {
			this.launchCmds = null;
		}

		if (properties.getProperty("aslr_disabler") != null) {
			aslrDisable = properties.getProperty("aslr_disabler");
		} else {
			aslrDisable = "";
		}

                if (properties.getProperty("launch_via_tracer") != null) {
                    this.launchViaPtracer = properties.getProperty("launch_via_tracer").equals("true");
                }

                if (properties.getProperty("signal_attached") != null) {
                    this.signalPtraceAttach = properties.getProperty("signal_attached").equals("true");
                }

    if (properties.getProperty("python_cmd") != null) {
        this.pythonCmd = properties.getProperty("python_cmd");
    } else {
        this.pythonCmd = DEFAULT_PYTHON;
    }
	}

	private Properties getProperties() {
		return this.properties;
	}

	public SimpleAlphabet<String> getAlphabet() {
		return alphabet;
	}

	public void setAlphabet(SimpleAlphabet<String> alphabet) {
		this.alphabet = alphabet;
	}

	private void parseLaunchCmds(String p) {
		this.launchCmds = new ArrayList<>();

		if (StringUtils.countMatches(p, '[') != StringUtils.countMatches(p, ']')) {
			System.err.println("Failed formatting of target_launch_cmds");
			System.exit(1);
		}
		int no_cmds = StringUtils.countMatches(p, '[');
		// For each flow
		for (int i = 1; i < no_cmds + 1; i++) {
			int start = StringUtils.ordinalIndexOf(p, "[", i);
			int end = StringUtils.ordinalIndexOf(p, "]", i);
			String cmd = p.substring(start + 1, end);
			launchCmds.add(cmd);
		}
	}

	private void parseFlows(String p) {
		this.bootstrapFlows = new ArrayList<>();

		if (StringUtils.countMatches(p, '[') != StringUtils.countMatches(p, ']')) {
			System.err.println("Failed formatting of expected flows 1");
			System.exit(1);
		}
		int no_flows = StringUtils.countMatches(p, '[');

		// For each flow
		for (int i = 1; i < no_flows + 1; i++) {
			int start = StringUtils.ordinalIndexOf(p, "[", i);
			int end = StringUtils.ordinalIndexOf(p, "]", i);
			String flow = p.substring(start + 1, end);

			if (StringUtils.countMatches(flow, '{') != StringUtils.countMatches(flow, '}')) {
				System.err.println("Failed formatting of expected flows 2");
				System.exit(1);
			}
			int queries = StringUtils.countMatches(flow, '{');

			ArrayList<String> inputs = new ArrayList<>();
			ArrayList<String> outputs = new ArrayList<>();
			// For each query/response
			for (int j = 1; j < queries + 1; j++) {
				int start_query = StringUtils.ordinalIndexOf(flow, "{", j);
				int end_query = StringUtils.ordinalIndexOf(flow, "}", j);
				String query_response = flow.substring(start_query + 1, end_query);
				int sep_index = query_response.indexOf(':');
				if (sep_index == -1) {
					String query = query_response;
					inputs.add(query);
				} else {
					String query = query_response.substring(0, sep_index);
					inputs.add(query);
					String response = query_response.substring(sep_index + 1);
					outputs.add(response);
				}
			}
			bootstrapFlows.add(new Flow<>(inputs, outputs));
		}
	}

	public String getOutputDir() {
		return outputDir;
	}

	public void setOutputDir(String outputDir) {
		this.outputDir = outputDir;
	}
}
