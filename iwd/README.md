# Usage

_This was tested on Ubuntu 18.04 which was running kernel 5.4.0-105-generic:_

1. Install dependencies: `sudo apt install libreadline-dev autotools-dev automake python-docutils libdbus-1-dev net-tools flex bison scapy virtualenv`.

2. Build iwd: `./build.sh`. When you switch kernel versions for some reason you should rebuild IWD.

3. Turn Wi-Fi off so your OS won't interfere with the tests.

4. Start iwd and virtual Wi-Fi interface: `sudo ./start.sh`. The script should automatically put IWD in AP mode.
   If that doesn't happen try to manually execute `./iwd-setap.py wlan0` followed by `iwctl ap wlan0 start test-network testing123`.
   Note that by default the _patched_ version of IWD is tested.

5. Start Wi-Fi learner: `cd greyboxstatelearning/hostapd/wifi-learner/src`. Then create a virtual Python environment and start the learner:

	virtualenv venv
	source venv/bin/activate
	pip install -r ../requirements.txt

   Become root, load the virtualenv again, and start it:

	sudo su
	source venv/bin/activate
	python Launcher.py -i wlan1 -t wlan2 -s test-network -p testing123 -m socket -g 192.168.0.1

6. Start the learner: `./run_learner.sh iwd-config.properties`


### Troubleshooting

On Ubuntu 18.04 building failed for me due to an outdated version of autotools/automake (error `WARNING: 'aclocal-1.16' is missing on your system`) I was able to fix with the below:

```
$ wget https://ftp.gnu.org/gnu/automake/automake-1.16.1.tar.gz
$ tar -xzvf automake-1.16.1.tar.gz
$ cd automake-1.16.1
$ ./configure  --prefix=/usr
$ make
$ make install
```


# Testing key reinstallations

To test for key reinstallations, you must use an old Linux kernel, or you can install drivers that are still vulnerable to key reinstallations by executing the `./get_drivers.sh` script.


# Testing unpatched IWD

You can undo `reinstall_fix.patch` to test the original IWD that was vunerable to a key reinstallation attack:

	patch -R -p2 < reinstall_fix.patch


# Findings

- We can replay Msg4/4 towards the AP to cause a key reinstallation. To trigger this bug,
  we should not use a new replay counter, but use exactly the same replay counter as the
  Msg4/4 that was sent previously.

