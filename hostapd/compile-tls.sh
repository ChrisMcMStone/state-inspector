#!/bin/bash
​
# Clean crypto, tls, and test executables
make -C ../src/crypto clean
make -C ../src/tls clean
rm test-https
rm test-https_server
​
# Build https client and server
make -j 6 test-https
make -j 6 test-https_server
​
echo ""
echo -e "\tServer: ./test-https_server 6666"
echo -e "\tClient: ./test-https localhost 6666 index.html"
echo ""
