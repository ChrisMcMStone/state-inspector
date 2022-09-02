# Testing the server

1. Build server and client: `cd greyboxstatelearning/hostapd-tls/ && ./build.sh`.

2. Start the server, this must be from the correct working directory: `cd hostap/tests/` and then execte `./hostaptls_srv 4500`.

3. Start the learner: `cd greyboxstatelearning/statelearner` and then execute `./run_learner.sh hostapdtls-server-config.properties`.


# Testing the client

0. Set `HOSTAPD` to true in `statelearner/src/tls/TLSTestService.java`.

1. Build server and client: `cd greyboxstatelearning/hostapd-tls/ && ./build.sh`.

2. Start the client. It will constantly keep trying to connect to the server: `greyboxstatelearning/hostapd-tls/hostap/tests/hostaptls_cli localhost 4500 index.html`.

3. Start the learner: `cd greyboxstatelearning/statelearner` and then execute `./run_learner.sh hostapdtls-client-config.properties`.


# Remarks

Specifying a timeout of 2000 miliseconds was import because Hostap's experimental TLS implementation can be rather slow. A low timeout would incorrectly miss many replies (the learner will assume there was no reply). Additionally, the learner would then already send the next message, while the server was still processing older ones. This is particularly problematic because the TLS implementation of Hostap cannot handle application data that "immediately" follows the handshake.

Primary state for server is stored in the `struct tlsv1_server` defined in `src/tls/tlsv1_server_i.h`. The state enum is at offset `0x0` and the total allocation size for this object is `0x298`.


# Findings

## General

- TLS Alerts are sent without encryption.

- There is no support for Heartbeat requests or responses. These frames are dropped before being
  decrypted by the receiver, causing the encryption to desynchronize between the client/server.

  This could be abused as a DoS attack (Hostap otherwise tries to ignore injected frames to keep
  the connection alive even when an adversary injects junk).

## Server

- Against the server, ApplicationDataEmpty always seem to be ignored. We haven't checked the client
  to see how it behaves.

- If the client sends, for example, the following sequence

		[{ClientHello}, {ClientKeyExchange}, {ClientCertificateVerify}]

  then the server returns a TLS Alert with error code "internal error". The debug output of the server is:

		TLSv1: No public key to verify signature
		TLSv1: Invalid Signature in CertificateVerify
		TLS: Invalid Signature in CertificateVerify
		TLSv1: Send Alert(2:80)

  The error is because `tls_verify_signature` fails. And it fails because `client_rsa_key` is NULL,
  since the client never send ClientCertificate. In other words, **the server tries to process packets**
  **that are sent in an invalid order**! However, this doesn't seem exploitable.

## Client

- Internal Error on [ServerHelloRSA, SeverHelloDone].

  When investigating the cause of this error, we found that against the client the `ServerKeyExchange` message
  can be skipped. That is, when the client receives the `ServerHelloDone` it will try to process it. However,
  the client will then hit an internal error condition when sending the ClientKeyExchange because it has not
  set an RSA key to encrypt the generated `pre_master_secret`.

  Further manual inspection revealed that when using an Ephemeral Diffie-Hellman handshake, this state machine
  bug is exploitable depending on the properties of the math library. In particular, when the client is executing
  a DHE handshake, it will calculate g^{cs} where s = 0 because it didn't receive a SeverKeyExchange. With the
  default math library of Hostap this exponentiation fails, leading to an internal error. However, when a user
  configures their own math library when compiling Hostap, this may result in an exploitable bug. In particular,
  the resulting shared key will be predictable, and an adversary can act as a rogue server.


# Background

Hostap provides a very basic internal TLS library. It is marked as experimental, but we found that both individual users and products use it in practice.

For instance, a [blog recommends to use the internal TLS library](https://blog.csdn.net/sean_8180/article/details/86496922) to save space (google translate: "Due to the small flash space on the development board, choose internal to save space."). An archived version of this blog is [available here](http://archive.is/Ge5r0).

When using [buildroot](https://buildroot.org/) to build an embedded Linux image, and you didn't explicitly configure it to use OpenSSL, the included hostap of buildroot will use its internal TLS implementation. One example of a product that has this kind of configuration is motionEyeOS. More information:

- Bulidroot: https://github.com/buildroot/buildroot

- motionEyeOS: https://github.com/ccrisan/motioneyeos

- The code in buildroot that selects the hostap TLS library to use is [https://github.com/buildroot/buildroot/blob/a08d5b4e64223452162a56a686390dcb8f68dfb7/package/hostapd/hostapd.mk#L31].

All combined, this makes it worthwhile to study the experimental TLS implementation of Hostap.

