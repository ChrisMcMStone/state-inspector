FROM ubuntu:16.04
LABEL maintainer="Sam L. Thomas"

# Triton dependencies
RUN apt-get update && apt-get dist-upgrade -y && \
    apt-get install -y software-properties-common apt-transport-https && \
    apt-get install -y git cmake build-essential clang ca-certificates curl \
    unzip libboost-dev

# Python 3.6
RUN add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y python3.6 python3.6-dev python3.6-venv && \
    apt-get clean

# get and install the latest z3 relesae
RUN cd /tmp && \
    curl -o z3.tgz -L  https://github.com/Z3Prover/z3/archive/z3-4.6.0.tar.gz && \
    tar zxf z3.tgz && cd z3-z3-4.6.0 && \
    CC=clang CXX=clang++ python3.6 scripts/mk_make.py && cd build && make -j4 \
    && make install && cd /tmp && rm -rf /tmp/z3-z3-4.6.0

# Install capstone
RUN cd /tmp && \
    curl -o cap.tgz -L https://github.com/aquynh/capstone/archive/4.0.1.tar.gz && \
    tar xvf cap.tgz && cd capstone-4.0.1/ && ./make.sh && make install && cd /tmp && \
    rm -rf /tmp/capstone-4.0.1

# Set up python venv
RUN python3.6 -m venv /root/tainter-venv && \
    . /root/tainter-venv/bin/activate && \
    pip install ipython z3 capstone networkx intervaltree && \
    cd /tmp && \
    curl -o master.zip -L https://github.com/JonathanSalwan/Triton/archive/master.zip && unzip master.zip && cd Triton-master/ && mkdir build && cd build && \
    cmake -G "Unix Makefiles" -DPYTHON36=on .. && make install && cd ..

# IDA Pro dependencies
RUN dpkg --add-architecture i386 && \
    cd /tmp && curl -o winehq.key https://dl.winehq.org/wine-builds/winehq.key && \
    apt-key  add winehq.key && \
    apt-add-repository -y 'deb https://dl.winehq.org/wine-builds/ubuntu/ xenial main' && \
    apt-get update && \
    apt-get install --install-recommends -y winehq-stable

ENTRYPOINT /bin/bash
