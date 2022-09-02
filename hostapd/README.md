# Hostapd

For testing the various WiFi handshakes (enterprise EAP methods, WPA3 etc), we want to begin by testing the WPA2-PSK 4-way handshake. This is a fairly simple protocol, which, like TLS, we have a client test harness already implemented ([here](https://github.com/ChrisMcMStone/wifi-learner)). 

The hostap submodule repository has been tweaked to make our greyboxstatelearning easier:

0. It contains some scripts to set up the testing environment.

1. It thinkgs all frames it sends are acknowledged (this can otherwise be a problem with mac80211_hwsim injection).

2. Retransmissions of EAPOL frames has been disabled. This can be enabled once we get state learning working without retransmissions.


## Set-up 

### First-time usage or new code

1. Update the hostap submodule with `git submodule init` followed by `git submodule update`, `cd hostap`, build with `./build.sh`.

2. Update the `greyboxstatelearning` repo to pull wifi-leaner submodule with `git submodule init` followed by `git submodule update` (or `git clone --recurse https://github.com/ChrisMcMStone/greyboxstatelearning/`).

3. Prepare a virtual python environment with the required dependencies for the wifi-learner (only needs to be done if requirements.txt changes):

	cd hostapd/wifi-learner
	python2 -m venv venv
	source venv/bin/activate
	pip install -r requirements.txt

### Repeated usage

1. Run `sudo hostapd/hostap/tests/hwsim/init.sh` to launch the simulated wifi network interfaces. (Note: requires `mac80211_hwsim` kernel module + `aircrack-ng`. This will kill your real wifi connection).

2. Launch `hostapd` with `sudo ./hostapd/hostap/hostapd/hostapd hostapd/hostap/tests/hwsim/hostapd.conf`

3. Start the wifi-learner test harness as follows:

	cd hostapd/wifi-learner
	sudo su
	source venv/bin/activate
	python src/Launcher.py -i wlan1 -t wlan4 -s test-network -p testing123 -g 192.168.0.1 -m socket

4. Finally launch the learner with the `statelearner/wifi-config.properties` file.

Instead of step 5 and 6, you can also run a standalone for tool testing excuding the learner by modifying filepaths in `run.sh` in `greyboxstatelearning/hostapd/run.sh`. Then run with script with with `sudo ./run.sh happy 1` , this will execute the wifi 4-way handshake and collect mem-dumps, malloc logs etc, which can then be fed to the `diff_tool.py` tool for example.


## State Info

State memory for the 4-way handshake is defined at `src/ap/wpa_auth_i.h` with the `struct wpa_state_machine` object. In our diff-tool outputs, this alloction will appear with a unique size of `0x310`. And the `wpa_ptk_state` member of this struct is located at the offset `0x20`.

There is also additional state memory (for STA management) held in the struct `src/ap/sta_info.h`. This alloction can be identified by it's unique size of `0x1d8`. 

## Debug notes

When including authentication & association frames our our alphabet and happy flow, we appear to suffer from non-determinism related issues in the `hwsim` mode of `hostapd`. I have dealt with this so some extent by including fuctionality in the learner to catch inconsistent query observations, and correct the model appropriately. This is fine during the main learning stage, however it's still not handled well if we get non-determinism in the bootstrap flows.

In the learning configuration, we have the option `bootstrap_mode` which can currently be set to `HAPPYFLOW` or `HAPPYFLOWMUTATED`. With the former, the issue is not problematic as the happy flow 99.99% runs deterministically. However with the later, where we mutate the happy flow in order to search for more state memory, problems seem to occur.  **TODO: This should now be fixed?**

In particular, in `HAPPYFLOW` mode we catch various bytes of memory pertaining to the `wpa_state_machine` object (identified with size `0x310`), and we also catch various bytes of memory within the `sta_info` object (identified with size `0x1d8`). This includes for example, the byte at offset `0x1b0` which is the `last_seq_ctrl` variable (Last Authentication/(Re)Association Request/Action frame sequence control). This is of particular interest as it behavious like a counter, so something we want to eliminate with our taint testing so learning can terminate.

However, in `HAPPYFLOWMUTATED` mode, our diff-tool excludes all this `sta_info` memory (`wpa_state_machine` seems ok) , including this counter in the `sta_info` object. On inspection I found that we had instances where "I/O equivalent" snapshots were being misclassified. For example, in the `grey_box_learner_wifi_error.zip` folder in this directory we have two snapshots taken in session 1 and 9 (`/tmp/grey_box_learner_wifi/dumpID-19_sessID-1_select.raw` and `/tmp/grey_box_learner_wifi/dumpID-34_sessID-9_select.raw'`) which according to the meta logs (`meta_1.log` and `meta_9.log`), are both tagged with equivalent I/O labels. 
Unfortunately though, it appears this classification is wrong as their values for e.g. the `last_seq_ctrl` which can be found in both files at the raw file offset of `0xBB60` (alloc offset `0x1b0`), has different values (`0x20` and `0x30`) indicating a different number of recieved auth/assoc requests. This means that the diff_tool disregards these values as being candidate state memory (when in fact they should be). 
The fact that in the session 1 snapshot is mem-dump ID 19, whereas in session 9 it is mem-dumpID 34, is also noteworthy and suggests there is a difference between these flows.

I think if we're to try to include the state memory related to the 802.11 sta management state machine we need this to be more reliable. If not possible, resets could be performed to bring the target the start of the 4-way handshake instead so we just focus on the EAPOL state data, but this will generally result in innacurate models since the EAPOL and STA management state machines work together. Moreover, the discovery of this `last_seq_ctrl` value is a nice example for the taint testing. 


## TLS Implementation

To test the TLS implementation of hostap, see the directory `hostapd-tls` in the greyboxstatelearning repository.

