#!/bin/bash
set -e

# sudo apt install autoconf libreadline-dev libdbus-1-3 libdbus-1-dev

cd iwd
./configure --enable-maintainer-mode \
		--enable-debug \
		--prefix=/usr \
		--localstatedir=/var \
		--enable-wired \
		--enable-hwsim \
		--enable-tools \
		--disable-manual-pages

make

echo "iwd requires dbus config to be installed."
echo "So we will now execute 'sudo make install'."

sudo make install
cd ..

