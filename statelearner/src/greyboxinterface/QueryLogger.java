package greyboxinterface;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class QueryLogger {

    private BufferedWriter out;
    final String LOG_EV_IN = "LOG_INPUT";
    final String LOG_EV_OUT = "LOG_OUTPUT";

    public QueryLogger(String filename) throws IOException {
        out = new BufferedWriter(new FileWriter(filename));
    }

    public void newInputMessage(String m) throws IOException {
        out.write(String.format("%d %s %s\n", System.nanoTime(), LOG_EV_IN, m));
        out.flush();
    }

    public void newOutputMessage(String m) throws IOException {
        out.write(String.format("%d %s %s\n", System.nanoTime(), LOG_EV_OUT, m));
        out.flush();
    }

    public void close() throws IOException {
        this.out.close();
    }
}
