# Contents

* [Installation guide with OpenSSL example](#set-up-guide)
* [Adding support for a new implementation/protocol](#addding-support-for-new-implementation)
* Case Studies
    - [OpenSSL](https://github.com/ChrisMcMStone/greyboxstatelearning/blob/master/openssl/)
    - [GnuTLS](https://github.com/ChrisMcMStone/greyboxstatelearning/blob/master/gnutls/)
    - [Hostapd](https://github.com/ChrisMcMStone/greyboxstatelearning/tree/master/hostapd/)
    - [Hypothetical](https://github.com/ChrisMcMStone/greyboxstatelearning/tree/master/exampleProtocols/BasicProtocol)

## CCS application notes:

**WolfSSL experiments:**  
results/wolf

**Experiment to demonstrate impact of running StateInspector without tainting:**  
results/no_taint  

^ This experiment was performed with a patched version of Statelearner, the patch is located at: `experiments/results/no_taint/MemoryEquivalenceOracle.java.diff`.
This patch comments out the logic in the learning algorithm which decides to use taint analysis. If code with this patch is run, if 2 states differ in state memory they will not be merged, and the learner will continue exploring.

The impact of this is likely to be non-termination, since without the ability to determine if differing memory is in fact relevant, the algorithm will never merge states with counters, and will explore infinitely. The openssl experiment is an example of this: repeatedly sending applicationEmpty messages and detecting a difference in state memory due to a counter.


## Set up guide

#### Dependencies

* Required
  - Clone this respository with `git clone --recurse-submodules https://github.com/ChrisMcMStone/greyboxstatelearning`
  - Maven (e.g. `sudo apt install maven`)
  - Other dependencies: `sudo apt install openjdk-14-jdk-headless maven python2 nodejs graphviz`
* Optional (configurable in learner properties file)
  - Taint analysis support - install manually with instructions [here](https://github.com/ChrisMcMStone/greyboxstatelearning/blob/master/statemem-taint/instructions.txt) or via a Docker container `sudo docker build -tag=“taint:Dockerfile” greyboxstatelearning/statemem-taint/Dockerfile`. Launch shell in this container with `sudo docker run -it taint:Dockerfile /bin/bash`. *TODO - update this once dockerisation fully implemented*
  - IDA-Pro - required by Triton for extracting binary basic blocks. `greyboxstatelearning/statemem-taint/res/idapro.tar.gz.enc` can be decrypted using instructions [here](https://github.com/ChrisMcMStone/greyboxstatelearning/blob/master/statemem-taint/res/decrypt.txt). This should then be installed within your WINE set-up.
  - Broswer based dynamic model rendering - depends on `node` which can be installed with ```curl -sL https://deb.nodesource.com/setup_13.x | sudo -E bash -``` and ```sudo apt-get install -y nodejs```. Then unzip the node libraries in the directory `cd greyboxstatelearning/js_mode_renderer/myapp` with `unzip libs.zip`. 

#### Compile tools

From greyboxstatelearning root directory:

* Ptrace - `cd ptrace-statemem && make statemem/statemem && cd ..`
* Learner - `cd statelearner && mvn package shade:shade && cd ..`

#### Set-up OpenSSL

From greyboxstatelearning root directory:

1. Extract and compile: `cd openssl && unzip openssl-b2d951e.zip && cd openssl-b2d951e && ./config && make && cd ../..`
2. Launch shell with ASLR disabled: e.g. ```setarch `uname -m` -R /bin/bash```
3. Start openssl server: `openssl/openssl-b2d951e/apps/openssl s_server -key openssl/server_key/diagserverCA.key -cert openssl/server_key/diagserverCA.pem -CAfile openssl/server_key/diagserverCA.pem -accept 4500 -www`

Note: these instructions can be followed in-combination with [this](https://github.com/ChrisMcMStone/greyboxstatelearning/blob/master/hostapd/README.md#set-up) for testing the WiFi handshake of hostapd. 

#### Configure & run learner

1. Modify `statelearner/openssl-config.properties` to match filepaths of your system. Including, `base_path`, `output_dir`, `bin_path` `extra_binaries`, `keystore_filename`, `keystore_password`. If Triton & IDA-Pro dependencies are installed, the `enable_taint_analysis=true` option can also be set, along with options for printing the source code at watchpoint hits with `print_watchpoint_hit_source_info=true`. You can set a custom python command using `python_cmd` -- useful if you are using a virtual environment; an example is given [here](statemem-taint/bin/symdep)).
2. Build statemem: `cd ptrace-statemem && make statemem/statemem`
3. Start the learner `cd statelearner && ./run_learner.sh openssl-config.properties`

To view the model of the learned state machine, we can use the node web-app which animates the contruction of the state machine in real time. If you have set the `inc_model_drawing=true` in the properties, and have installed node as described aboe, you can open a web-browser at `http://localhost:3000/index.html`. 

Alternatively we can open the PDF model which is generated upon learning termination: `evince /output_dir/full_model.pdf`. A more succint/readable version of the model can be generated with the `sudo /statelearner/model_cleaner.py /output_dir/full_model.dot && dot -Tpdf -O /output_dir/full_modelstripped.dot && evince /output_dir/full_modelstripped.dot.pdf`

#### Debugging

You can modify the debugging output verbosity by editing the file `statelearner/src/logging.properties`.

## Adding support for new implementation

#### Test Harness

A test harness is required for each protocol and can be shared across implementations of the same protocol. There are two ways one can implement a test harness:
* Directly in the `statelearner` Java project, as done with the TLS test harness (see `statelearner/src/tls/TLSSUL.java`). Or,
* Independently, with whichever langauge desired. Your test harness will communicate with the learner over a TCP connection, using the `statelearner/src/socket/SocketSUL.java` interface. The connection details are configurable in the `properties` file. 
  - The test harness should be able to process all inputs specified by the `alphabet` properties parameter, and additionly the `RESET` command to force the target to the start state. The test harness should return the string `Empty`, if the target does not respond to an input within your specified timeout. 
  - [Optional] By default, the learner will handle the timestamped I/O log generation (for tagging snapshots with the I/O metadata). However, it particularly time sensitive applications, it may be desireable to implement this in the test harness. We do exactly this with `hostap`. Here, we set the `harness_side_logging=true` in the properties file, and then each `RESET` command at the start of a query will now take the form `RESET:/file/path/to/io_log_for_sessionID` - this filepath informs the test harness where to write the I/O log too. 
  - Examples of this type of test harness can be found with the [hypothetical](https://github.com/ChrisMcMStone/greyboxstatelearning/tree/master/exampleProtocols/TestHarness) and [hostapd](https://github.com/ChrisMcMStone/wifi-learner/blob/master/src/Launcher.py#L210) implementations.

#### Implement custom ptrace-statemem hooking method

The tool we use for to dump memory snapshots needs to be adapted to support the new implementation. In particular, we need to modify the C file `ptrace-statemem/statemem/statemem.c` as follows:

* Implement a method of the form `static void post_call_dump_heap_APPNAME(trace *t, void *data)`. A template is provided on line 533. To automatically identify the syscall hooking parameters specified in the above method, we have provided a tool named iolearn. To use:
  * Navigate to `/greyboxstatelearning/ptrace-statemem`, run `make iolearn/iolearn`. Launch your target binary and then determine it's PID. Then run ```sudo ptrace-statemem/iolearn/iolearn -pid `pgrep appname` -session-id 1```.
  * Execute the *happy flow* of the protocol against your target (using your test harness), and let iolearn generate a syscall log for later processing. Kill iolearn, and the log `appname_1.log` will be written.
  * Then execute the python script `python3 greyboxstatelearning/iolearner/iolearn.py --log /path/to/appname_1.log`. Output will look something like : ```[{"fd": 6, "syscalls": [20, 45]}]```, where `fd` is the socket file descriptor, and the `syscalls` numbers are the read and write syscall IDs respectively. 
* Add a support for registering this newly implemented hooking method via a `ptrace-statemem` command line arg named `-app`. See lines 805-823 for how this is implemented for openssl, hostapd etc..
