#!/bin/bash
set -e

APPSERVER=hostaptls_srv
APPCLIENT=hostaptls_cli

# On first build, pull in Hostap 2.9 sources
if [[ ! -d hostap ]]; then
	git clone --branch hostap_2_9 git://w1.fi/srv/git/hostap.git
    cd hostap && git am ../*.patch && cd ..
fi
cd hostap/tests/

# Clean crypto, tls, and test executables
make -C ../src/crypto clean
make -C ../src/tls clean
rm -f test-https test-https_server $APPSERVER $APPCLIENT

# Build https client and server
make -j 4 test-https
make -j 4 test-https_server

# Rename to short filenames
mv test-https $APPCLIENT
mv test-https_server $APPSERVER

# Instructions for manual testing
echo ""
echo -e "\tServer *MUST* be executed from the following directory:"
echo -e ""
echo -e "\tcd $PWD"
echo -e ""
echo -e "\tServer: ./$APPSERVER 4500"
echo -e "\tClient: ./$APPCLIENT localhost 4500 index.html"
echo ""
