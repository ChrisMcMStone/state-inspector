#!/bin/bash

# arg1 = name of file containing line separated queries
# arg2 = session_id (needs to be unique per run)

MEM_DUMPER_DIR=/home/chris/Documents/phd/hw_symb/grey_box/greyboxstatelearning/ptrace-statemem/statemem
SNAP_DIR=`pwd`
LOGGER_DIR=/home/chris/Documents/phd/hw_symb/grey_box/greyboxstatelearning/logger

sess_id="$2"
ctrl_log="hostapd$sess_id.log"
query_interface=/home/chris/Documents/phd/protocol_learning/wifi/wifi-learner/src/Launcher.py
query_file_dir=/home/chris/Documents/phd/protocol_learning/wifi/wifi-learner/src/
queries=$1

# Currently this is hardcoded in ptrace-statemem
dump_log="dump$sess_id.log"

dumper_runner="sudo $MEM_DUMPER_DIR/statemem -app hostapd -save-mappings -session-id $sess_id -trace-malloc malloc$sess_id.log -dump-dir $SNAP_DIR &"

query_runner="sudo python $query_interface -i wlan4mon -t wlan1mon -s test-network -p testing123 -m $query_file_dir$queries -g 192.168.0.1 -l $ctrl_log"

echo $dumper_runner
eval $dumper_runner
eval $query_runner

pkill -2 statemem

logger="python3 $LOGGER_DIR/logger.py --root $SNAP_DIR --ctrl $ctrl_log --dump $dump_log --malloc malloc$sess_id.log --out $1_$sess_id.log"
echo $logger
eval $logger
