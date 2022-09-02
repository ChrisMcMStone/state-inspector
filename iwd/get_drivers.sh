#!/bin/bash

rm -rf backports-5.8-1
wget https://cdn.kernel.org/pub/linux/kernel/projects/backports/stable/v5.8/backports-5.8-1.tar.xz
tar -xvf backports-5.8-1.tar.xz
rm backports-5.8-1.tar.xz
cd backports-5.8-1
patch -p1 < ../backports.patch
make defconfig-hwsim
make -j 4
sudo make install
