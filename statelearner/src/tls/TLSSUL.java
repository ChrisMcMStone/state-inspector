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

package tls;

import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Logger;

import de.learnlib.api.exception.SULException;
import greyboxinterface.QueryLogger;
import learner.StateLearnerSUL;
import net.automatalib.words.impl.SimpleAlphabet;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class TLSSUL implements StateLearnerSUL<String, String> {

	private static Logger log = Logger.getLogger(TLSSUL.class.getName());

	SimpleAlphabet<String> alphabet;
	TLSTestService tls;
	TLSConfig config;
	QueryLogger qLog;
	private int sessionID;

	public TLSSUL(TLSConfig config) throws Exception {
		alphabet = new SimpleAlphabet<String>(Arrays.asList(config.alphabet.split(" ")));

		this.config = config;
		tls = new TLSTestService();
		tls.setTarget(config.target);
		tls.setHost(config.host);
		tls.setPort(config.port);
		tls.setCommand(config.cmd);
		tls.setRequireRestart(config.restart);
		tls.setReceiveMessagesTimeout(config.timeout);
		tls.setKeystore(config.keystore_filename, config.keystore_password);
		tls.setConsoleOutput(config.console_output);

		if (config.version.equals("tls10")) {
			tls.useTLS10();
		} else {
			tls.useTLS12();
		}
	}

	public SimpleAlphabet<String> getAlphabet() {
		return alphabet;
	}

	public boolean canFork() {
		return false;
	}

	public void setUp() {
		try {
			this.tls.start();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public String step(String symbol) {
		String result = null;
		try {
			qLog.newInputMessage(symbol);
			result = tls.processSymbol(symbol);
			qLog.newOutputMessage(result);
		} catch (Exception e) {
			log.severe("Failed to write input symbol to socket or query logger I/O error.");
			throw new SULException(e.getCause());
		}
		return result;
	}

	public void pre() {
		try {
			tls.reset();
			String logFilename = config.getOutputDir() + "/" + config.appName + sessionID + ".log";
			this.qLog = new QueryLogger(logFilename);
		} catch (Exception e) {
			log.severe("Failed to reset TLSSUL or query logger I/O error.");
			throw new SULException(e);
		}
	}

	@Override
	public void post() {
	}

	@Override
	public void updateSessionID(int sessionID) {
		this.sessionID=sessionID;
	}

	@Override
	public void toggleSlowReset() throws Exception {
		throw new Exception("TLS SUL does not support SLOW resets.");
	}
}
