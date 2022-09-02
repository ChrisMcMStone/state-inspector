#!/bin/sh
set -e

BASE=$(basename `pwd`)

if [ "$BASE" != "statelearner" ]; then
    echo "ERROR: Run from statelearner directory"
    exit 1
fi

if [ $(id -u) = 0 ]; then
   echo "ERROR: Do not run as root."
   exit 1
fi

if [ -z "$1" ]; then
    echo "ERROR: missing parameter - learner properties config file"
    echo "e.g: ./run_learner.sh openssl-config.properties"
    exit 1
fi

NEWEST_PTRACE=$(find ../ptrace-statemem -name '*.c*' -printf '%T+ %p\n' | sort -r | head -1 | cut -d ' ' -f2)
PTRACE_SRC=$(stat $NEWEST_PTRACE -c %Y)
PTRACE_BIN=$(stat ../ptrace-statemem/statemem/statemem -c %Y)
if [ "$PTRACE_SRC" -gt "$PTRACE_BIN" ]; then
    cd ../ptrace-statemem
    make statemem/statemem
    cd ../statelearner
fi

JAR=target/memlearnlib-1.jar
if [ -f "$JAR" ]; then
    NEWEST_SRC=$(find ./src -name '*.java' -printf '%T+ %p\n' | sort -r | head -1 | cut -d ' ' -f2)
    FILETIME_JAR=$(stat $JAR -c %Y)
    FILETIME_SRC=$(stat $NEWEST_SRC -c %Y)

    # Check if file older
    if [ "$FILETIME_SRC" -gt "$FILETIME_JAR" ]; then
       mvn package shade:shade
    fi
else
    mvn package shade:shade
fi

mkdir -p logs/

USRNAME=$(whoami)
run="sudo java -Djava.util.logging.config.file=./src/logging.properties -Duser.name=$USRNAME -jar target/memlearnlib-1.jar $1"

echo $run
eval $run
