# Summary

We discovered that a WolfSSL server accepts TLS handshake messages that cannot be sent by a
client. For instance, a WolfSSL server will accept and process a ServerHello message. The
same was found in the client: it accepts TLS handshake messages that cannot be sent by a
server. For instance, a WolfSSL client will accept and process a ClientHello message.

We created an example attack that abuses this vulnerability against a client. In particular,
when the client is configured to use PSK ciphersuites and has SNI enabled, then an adversary
can abuse the discovered vulnerability to make the client enter an infinite loop.

Due to the complexity of the TLS code and all possible exploit scenarios it is infeasible to
exhaustively explore all attack scenarios. We therefore conjecture that other types of attacks
may also be feasible and that servers are also vulnerable to attacks. We discuss two possible
attack scenarios against against servers, namely bypassing client authentication and replaying
old sessions, with the remaining hurdle being the spoofing of the last Finished message towards
the server.


# Attacking the Client: Infinite Loop

This attack allows an adversary to put a client into an infinite loop. We first explain the
steps behind the attack and then give proof-of-concept code. The attack only works when the
client is configured to use [PSK ciphersuites](https://datatracker.ietf.org/doc/html/rfc4279)
and when WolfSSL is compiled with SNI support (e.g. perhaps in embedded devices).

## Infinite Loop Attack

0. We assume the adversary has a machine-in-the-middle position. The adversary will send
   responses to the client (no real server is involved in the attack).

1. Once the client connects to the server, we must first send a ServerHello to the client. This
   is because the WoflSSL client requires that the first message it receives from the server must
   be a ServerHello.

2. The attacker will now send a ClientHello to the client. WolfSSL will do some sanity checks
   and only by offering a PSK ciphersuite can these checks be passed (at least based on our
   current knowledge). This means the client must be configured to support PSK ciphersuites.
   While processing the ClientHello, the WolfSSL client will mark itself as a server. See
   `src/internal.c:DoClientHello`:

	    #endif
	    #ifdef HAVE_SNI
		        if((ret=SNI_Callback(ssl)))
		            goto out;
		        ssl->options.side = WOLFSSL_SERVER_END;
	    #endif

   As can be seen from this code sniplet, this will only happen if SNI has been enabled.

3. The WolfSS client will continue a normal handshake (by sending normal client-side messages).
   After it transmitted the CCS and Finished packet, it will think the handshake has been
   completed (because it marked itself as being a server). See `src/internal.c:SendFinished`:

	    if (!ssl->options.resuming) {
	#ifndef NO_SESSION_CACHE
		AddSession(ssl);    /* just try */
	#endif
		if (ssl->options.side == WOLFSSL_SERVER_END) {
		#ifdef OPENSSL_EXTRA
		    ssl->options.serverState = SERVER_FINISHED_COMPLETE;
		    ssl->cbmode = SSL_CB_MODE_WRITE;
		    if (ssl->CBIS != NULL)
		        ssl->CBIS(ssl, SSL_CB_HANDSHAKE_DONE, SSL_SUCCESS);
		#endif
		    ssl->options.handShakeState = HANDSHAKE_DONE;
		    ssl->options.handShakeDone  = 1;
		}
	    }

4. **The client now accepts plaintext ApplicationData records**! That's because it thinks the
   handshake is completed but it hasn't yet enabled decryption of incoming records. And on
   reception of ApplicationData it's only checked whether the handshake has completed:

	    if (ssl->options.handShakeDone == 0) {
		WOLFSSL_MSG("Received App data before a handshake completed");
		SendAlert(ssl, alert_fatal, unexpected_message);
		return OUT_OF_ORDER_E;
	    }

   When the WolfSSL client now tries to process a plaintext ApplicationData record it gets
   stuck in an infinite loop. The problem is that `ssl->keys.encryptSz` is never set to a
   value by no decryption happens, and this variable is used to calculate the amount of data
   in the ApplicationData record.

   That the client gets stuck in an infinite loop, instead of processing plaintext data, is
   coincidence. Any forks of WolfSSL that slightly changed how ApplicationData frames are
   decrypted/handled might be vulnerable to more serious attacks where plaintext data can
   be sent towards a client.

5. The client gets stuck in an infinite loop (see above).


## Proof-of-concept

Get the WolfSSL code and the revision we tested the attack against:

	git clone https://github.com/wolfSSL/wolfssl.git
	cd wolfssl
	git checkout d487916557fc1e017978359577c97009369f5e0e

Note that commit be3b6b47efe20f96b4a2c43e7183e114b3f90d6d ("DTLS MTU fixes") no longer causes
the client to enter in an infinite loop. This highlights that seemingly innocent code changes
can affect the exploitability of a vulnerability (i.e. benign changes can suddenly make something
exploitable and vice versa). Let's compile the above example revision:

	./autogen.sh
	./configure --enable-opensslextra --enable-psk --enable-sni
	make

Create keys for the attacker's TLS server:

	openssl req -x509 -newkey rsa:2048 -keyout mykey.pem -out mycert.pem -days 365 -nodes -subj '/CN=server.com/O=Org/C=US'

Now you can copy ./mitm.py the script to the root of the woflssl directory and execute:

	./mitm.py

And finally connect using the victim client:

	./examples/client/client -h 127.0.0.1 -p 8080 -s -l PSK-CHACHA20-POLY1305

**The client will now get stuck in an infinite loop**.


# Concerning Server Behaviour: Resuming Invalid Session

In this scenario we trick the server (that may be using client authentication) to use an
all-zero `masterSecret`. This means we can send arbitrary encrypted records towards it.
We have not yet found a technique to spoof the last Finished message towards the server,
meaning the practical impact of this scenario is unclear, though it highlight the fragility
that our discovered vulnerability causes. We first describe the attack scenario and then
present a script to experiment with this scenario.


## Attack Steps Explanation

1. The attacker sees a legitimate client connect to the server. It will capture the session ID
   that is being created.

2. The attacker sends a ClientHello that will resume the legitiate session above by including
   the captured session ID. Note that the adversary does not know the keys corresponding to
   this session.

3. The server will reply using a ServerHello, ChangeCipherSpec, and encrypted Finish message.
   After sending the CCS message the server will generate the encryption keys used to send
   encrypted records. At this point it still accepts plaintext handshake frames (as it should).

4. The adversary now sends a ServerHello to the server. This ServerHello includes an all-zero
   session ID. The server, which acts as a client while processing the ServerHello, will have
   it's "session resumption fields" in its state all initialized to zero. This means it will
   think the all-zero session ID corresponds to a valid session (because in function `DSH_CheckSessionId`
   the session ID in the ServerHello is equal to the all-zero field `ssl->session.sessionID`).
   In this turn causes `ssl->session.masterSecret` to be used as the MasterSecret, and this
   field consists of all-zeros (because the server never used/initialized these clients fields).
   
   This means the server will now configure encryption keys based on: (1) all-zero MasterSecret;
   (2) the clientRandom that we sent; and (3) the serverRandom in our injected ServerHello. This
   means we know the _handshake_ keys it's now using. Note that we don't know the keys that the
   server installed in attack step (3) to decrypt frames.

5. The adversary now sends a ChangeCipherSpec to the server. This will cause the server to generate
   the encryption keys used to decrypt incoming records. It will not reconfigure its encryption keys
   that were installed in step (3) of the attack. **This means the adversary can now send encrypted**
   **records to the server, which the server will successfully decrypt.** Under normal conditions
   this is impossible when the server uses client authentication (and the adversary doesn't possess
   a valid certificate).

6. To complete the handshake, the adversary needs to send a valid Finished message to the server.
   The digest in this finished message must be computed over all handshake messages that the server
   sent and received, including the Finished message that the server transmitted in step 3.
   However, the adversary doesn't know the digest value in the Finished message sent by the server.
   This is because the Finished message is sent encrypted and the digest was still calculated using
   the legitimate (non-zero) masterSecret. As a result, we cannot send a Finished message that the
   server will accept, because the adversary cannot compute a valid digest.
   

It's unclear whether other attack techniques can be used to complete the handshake. In any case,
we consider it highly concerning that the server is using an all-zero masterSecret.


## Proof-of-concept of the attack

Apply the attached patch

	git clone https://github.com/wolfSSL/wolfssl.git
	cd wolfssl
	git checkout ae0cefc48da570feaa14f2960801d14ea7959149

	# This is to debug the attack scenario easily:
	patch -p1 < output_keys.patch

Compile using:

	./autogen.sh
	./configure
	make

Generate the following keys to illustrate with client authentication:

	openssl req -x509 -newkey rsa:2048 -keyout mykey.pem -out mycert.pem -days 365 -nodes -subj '/CN=server.com/O=Org/C=US'

	openssl req -x509 -newkey rsa:2048 -keyout ClientRootCA.key -out ClientRootCA.pem -days 1024 -nodes -subj '/CN=clientroot.com/O=Org/C=US'

	openssl genrsa -out MyClient1.key 2048
	openssl req -new -key MyClient1.key -out MyClient1.csr  -subj '/CN=client1.clientroot.com/O=Org/C=US'

	# The following is needed because WolfSSL only accepts certificates of version 3
	echo "authorityKeyIdentifier=keyid,issuer" >> v3.ext
	echo "basicConstraints=CA:FALSE" >> v3.ext
	echo "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment" >> v3.ext

	openssl x509 -req -in MyClient1.csr -extfile v3.ext -CA ClientRootCA.pem -CAkey ClientRootCA.key -CAcreateserial \
		-out MyClient1.pem -days 1024 -sha256

Now start the server that we will attack:

	./examples/server/server -p 44330 -c mycert.pem -k mykey.pem -A ClientRootCA.pem -i

Now you can copy ./mitm.py the script to the root of the woflssl directory and execute:

	./mitm.py --server



# Concerning Server Behaviour: Replaying an old Handshake

In this scenario we make the server overwrite its `serverRandom` value. This can be used
to make the server generate the same keys as in a previous TLS session (if that session
didn't use ephemeral ciphers). We have not yet found a technique to spoof the last Finished
message towards the server, meaning the practical impact of this scenario is unclear,
though it highlight the fragility that the vulnerability causes. We only describe this
attack scenario (no scripts were made to experiment with it).


## Replaying an old handshake and data

1. The attacker sees a legitimate client connect to the server. It will capture all
   handshake frames.

2. The attacker replays the ClientHello sent by the legitimate client. The server will
   respond with a ServerHello that contains a random `serverRandom`.

3. The attacker spoofs a ServerHello with the `serverRandom` field equal to the random
   value used in the connection that we are trying to replay. The attacker sends this
   ServerHello to the server. As a result, the server will overwrite its `serverRandom`
   with the one sent by the attacker.

4. The adversary replays the ClientKeyExchange and ChangeCipherSpec towards the server.

5. The adversary cannot replay the Finished message of the legitimate handshake because
   its digest will not be correct (due to the forged ServerHello that we sent to the server in
   step 3 of the attack). This means we cannot complete the handshake.

It's unclear whether other attack techniques can be used to complete the handshake. In any case,
we consider it highly concerning that the server has generated the same keys as in a previous
handshake with a legitimate client.

