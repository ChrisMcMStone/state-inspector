package socket;

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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.util.Arrays;
import java.util.logging.Logger;

import de.learnlib.api.SUL;
import de.learnlib.api.exception.SULException;
import greyboxinterface.QueryLogger;
import learner.Config;
import learner.StateLearnerSUL;
import net.automatalib.words.Word;
import net.automatalib.words.impl.SimpleAlphabet;

public class SocketSUL implements StateLearnerSUL<String, String> {

	private static Logger log = Logger.getLogger(SocketSUL.class.getName());

	SocketConfig config;
	SimpleAlphabet<String> alphabet;
	Socket socket;
	BufferedWriter out;
	BufferedReader in;
	QueryLogger qLog;
	private int sessionID;
	private boolean slowReset = false;

	public SocketSUL(SocketConfig config) throws Exception {
		this.config = config;
		alphabet = new SimpleAlphabet<String>(Arrays.asList(config.alphabet.split(" ")));

		// Initialise test service
		socket = new Socket(config.hostname, config.port);
		socket.setTcpNoDelay(true);
		out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
		in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	}

	public SimpleAlphabet<String> getAlphabet() {
		return alphabet;
	}

	public String step(String symbol) {
		String result = "";
		try {
			// Process symbol and return result
			out.write(symbol + "\n");
			if(!config.harness_side_logging) qLog.newInputMessage(symbol);
			out.flush();
			result = in.readLine();
                        if(result == null) result = "";
			if(!config.harness_side_logging) qLog.newOutputMessage(result);
		} catch (IOException e) {
			log.severe("Failed to write input symbol to socket. ");
			throw new SULException(e.getCause());
		}
		return result;
	}

	public String queryToString(Word<String> query) {
		StringBuilder builder = new StringBuilder();
		boolean first = true;
		for (String input : query) {
			if (first) {
				first = false;
			} else {
				builder.append(config.delimiter_input);
			}
			builder.append(input);
		}
		return builder.toString();
	}

	public Word<String> wordFromResponse(String response) {
		String[] outputs = response.split(config.delimiter_output);
		return Word.fromArray(outputs, 0, outputs.length);
	}

	public Word<String> stepWord(Word<String> query) {
		try {
			out.write(queryToString(query)); // Each input in query is separated by
												// space when using .toString()
			out.write("\n");
			out.flush();

			String response = in.readLine();
			return wordFromResponse(response);
		} catch (IOException e) {
			log.severe("Failed to write word to socket. ");
			throw new SULException(e.getCause());
		}
	}

	public boolean canFork() {
		return false;
	}

	public SUL<String, String> fork() throws UnsupportedOperationException {
		throw new UnsupportedOperationException("Cannot fork SocketSUL");
	}

	public void pre() {
		try {
			String logFilename = config.getOutputDir() + "/" + config.appName + sessionID + ".log";
			String resetPrefix = this.slowReset ? "SLOW"  : "";
			if (config.harness_side_logging) {
				out.write(resetPrefix+"RESET:"+logFilename+"\n");
			} else {
				out.write(resetPrefix+"RESET\n");
			}
			// Reset test service
			out.flush();
			in.readLine();
			if (!config.harness_side_logging) {
				this.qLog = new QueryLogger(logFilename);
			}
		} catch (Exception e) {
			log.severe("Failed to reset Socket SUL. ");
			throw new SULException(e.getCause());
		}
	}

	public void post() {
	}

	@Override
	public void updateSessionID(int sessionID) {
		this.sessionID = sessionID;
	}

	@Override
	public void setUp() {

	}

	@Override
	public void toggleSlowReset() {
		this.slowReset = !this.slowReset;
	}
}
