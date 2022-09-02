from avatar2 import Avatar, X86_64, PandaTarget
import argparse

import select
import datetime
import sys
import os
import logging
import serial
import time
import paramiko 
import mem_dumps

sys.path.append("../..")

l = logging.getLogger('hostapd')
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

PANDA_PATH = "/home/chris/Documents/phd/hw_symb/avatar-panda-terrace/build/x86_64-softmmu/qemu-system-x86_64"
PANDA_SNAPSHOT = " -hda /home/chris/Documents/phd/hw_symb/panda/debian_c.qcow2"
PANDA_ARGS = " -m 1024 -loadvm no_aslr -redir tcp:2222::22 -gdb tcp::1235 -S -qmp tcp:127.0.0.1:3334,server,nowait -nographic"
PANDA_CMDLINE = PANDA_PATH + PANDA_SNAPSHOT + PANDA_ARGS

PANDA_RECORDS = '/home/chris/Documents/phd/hw_symb/panda/records/'

def record_trace(record_file, queries):
    PANDA_ENTRY = 0x47c740  # handle_auth()
    #PANDA_EXIT = 0x4175A0   # send mlme response

    avatar = Avatar(arch=X86_64, output_directory=PANDA_RECORDS)

    panda = avatar.add_target(PandaTarget, 
                              executable=PANDA_PATH,
                              gdb_executable="gdb",
                              gdb_port=1235,
                              name='panda')

    panda.init(cmd_line=PANDA_CMDLINE.split())
    l.info("Initialized Target")
    panda.set_breakpoint(PANDA_ENTRY)
    panda.cont()

    ssh_client=paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname='127.0.0.1',username='root',password='123456',port=2222)
    l.info("SSH Connection Succeeded. Running hostapd and client...")
    #channel1 = ssh_client.get_transport().open_session()
    #channel1.exec_command('/home/user/hostap/hostapd/hostapd /home/user/hostap/tests/hwsim/hostapd.conf &')
    channel2 = ssh_client.get_transport().open_session()
    if queries:
        sftp = ssh_client.open_sftp()
        sftp.put(queries, '/home/user/wifi-learner/src/queries')
    l.info("Running query:")
    stdin,stdout,stderr = ssh_client.exec_command('cat /home/user/wifi-learner/src/queries')
    l.info(stdout.readlines())
    channel2.exec_command('cd /home/user/wifi-learner/src && ./run.sh')

    panda.wait()
    l.info("Reached breakpoint, starting recording.")
    ##panda.set_breakpoint(PANDA_EXIT)

    panda.begin_record(record_file)

    ##Block until handshake completed
    panda.cont()

    while not channel2.exit_status_ready():
       time.sleep(1)
       if channel2.recv_ready():
           # Only print data if there is data to read in the channel
           rl, wl, xl = select.select([channel2], [], [], 0.0)
           if len(rl) > 0:
               # Print data from stdout
               print("Output: {}".format(channel2.recv(1024).decode("utf-8")))

    panda.stop()
    l.info("Reached end of execution, end record")
    panda.end_record()


if __name__ == '__main__':
    CLI=argparse.ArgumentParser()
    CLI.add_argument( "--record", help="filename of PANDA record, defaults to a timestamp name", default=None)
    CLI.add_argument("--queries", help="4-way handshake query to run", default=None)
    CLI.add_argument("-m", action='store_true', help="whether or not to replay PANDA record afterwards and perform RAM dumps at given address in mem_dumps.py")

    args = CLI.parse_args()

    if(args.m and not args.record):
        parser.error("A record name --record must be specified if performing memory dumps")

    if(not args.record):
        args.record = "record" + str(datetime.datetime.now().date()) + '_' + str(datetime.datetime.now().time()).replace(':', '.')

    record_trace(args.record, args.queries)

    if(args.m):
        mem_dumps.mem_dumps(args.record)
