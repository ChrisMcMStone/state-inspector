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

package utils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;

import datastructures.FastMealyMemModel;
import learner.Config;
import net.automatalib.automata.transducers.impl.compact.CompactMealy;
import net.automatalib.serialization.dot.GraphDOT;

public class Utils {
	private static String CHARS = "0123456789ABCDEF";

	public static String bytesToHex(byte[] bytes) {
		StringBuffer hex = new StringBuffer();

		for (int i = 0; i < bytes.length; i++) {
			int n1 = (bytes[i] >> 4) & 0x0F;
			hex.append(CHARS.charAt(n1));
			int n2 = bytes[i] & 0x0F;
			hex.append(CHARS.charAt(n2));
		}

		return hex.toString();
	}

	public static byte[] hexToBytes(String hex) {
		if (hex.length() % 2 != 0)
			hex = "0" + hex;

		byte[] bytes = new byte[hex.length() / 2];

		for (int i = 0; i < hex.length(); i = i + 2) {
			bytes[i / 2] = Integer.decode("0x" + hex.substring(i, i + 2)).byteValue();
		}

		return bytes;
	}

    public static boolean isDisabled(String o, ArrayList<String> disabled) {
        return disabled.stream().anyMatch(dis -> o.contains(dis));
    }

    public static boolean isEmpty(String o, ArrayList<String> empty) {
        return empty.stream().anyMatch(dis -> o.contains(dis));
	}
	
	
    // --------------------- MODEL DRAWING--------------------------

    public static void drawModel(Config config, FastMealyMemModel<?,?> model) throws FileNotFoundException, IOException, InterruptedException {
        drawModel(config, model, "test.dot", false);
    }
    public static void drawModel(Config config, FastMealyMemModel<?,?> model, String filename, boolean toPdf) throws FileNotFoundException, IOException, InterruptedException {
        if (!config.incModelDrawing)
            return;

        File dotFile = new File(config.outputDir + "/" + filename);
        PrintStream psDotFile = new PrintStream(dotFile);
        GraphDOT.write(model, psDotFile);
        psDotFile.close();

        Process p = Runtime.getRuntime()
                .exec(config.pythonCmd + " " + config.modelCleanerPath + " " + config.outputDir + "/" + filename);
        p.waitFor();

        File dotFileUnformatted = new File(config.outputDir + "/unformatted_" + filename);
        PrintStream psDotFileUnformatted = new PrintStream(dotFileUnformatted);
        GraphDOT.write(model, psDotFileUnformatted);
        psDotFile.close();

		// Convert .dot to .pdf
		if (toPdf) Runtime.getRuntime().exec("dot -Tpdf -O " + config.outputDir + "/" + filename);
	}

    public static void drawModel(Config config, CompactMealy<?,?> model, String filename, boolean toPdf) throws FileNotFoundException, IOException, InterruptedException {
        if (!config.incModelDrawing)
            return;

        File dotFile = new File(config.outputDir + "/" + filename);
        PrintStream psDotFile = new PrintStream(dotFile);
        GraphDOT.write(model, psDotFile);
        psDotFile.close();

        Process p = Runtime.getRuntime()
                .exec(config.pythonCmd + " " + config.modelCleanerPath + " " + config.outputDir + "/" + filename);
        p.waitFor();

        File dotFileUnformatted = new File(config.outputDir + "/unformatted_" + filename);
        PrintStream psDotFileUnformatted = new PrintStream(dotFileUnformatted);
        GraphDOT.write(model, psDotFileUnformatted);
        psDotFile.close();

		// Convert .dot to .pdf
		if (toPdf) Runtime.getRuntime().exec("dot -Tpdf -O " + config.outputDir + "/" + filename);
    }

}
