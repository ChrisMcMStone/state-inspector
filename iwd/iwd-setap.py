#!/usr/bin/python3
import dbus, sys, socket, subprocess

if len(sys.argv) != 2:
	print(f'Usage: {sys.argv[0]} <device>')
	exit(1)

def device2phyidx(device):
	output = subprocess.check_output(["iw", device, "info"])
	line = list(filter(lambda n: b"wiphy" in n, output.split(b"\n")))[0]
	idx = int(line.split()[1])
	return idx

device = sys.argv[1]
index = device2phyidx(device)
ifindex = socket.if_nametoindex(device)

bus = dbus.SystemBus()
object_path = f"/net/connman/iwd/{index}/{ifindex}"
obj = bus.get_object('net.connman.iwd', object_path)
dbus_device = dbus.Interface(obj, 'org.freedesktop.DBus.Properties')
dbus_device.Set('net.connman.iwd.Device', 'Mode', 'ap')

print(f"Interface {device} is now in AP mode. To start AP execute:")
print(f"\tiwctl ap {device} start test-network testing123")
