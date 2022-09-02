# Old Ideas and Notes

## Simulate normal PSK handshake

openssl s_server -nocert -accept 44331 -www -psk fcc56e7668194a4775e5b36e2735551a -cipher 'DHE-PSK-AES256-GCM-SHA384'
openssl s_client -connect localhost:44331 -psk fcc56e7668194a4775e5b36e2735551a -tls1_2 -cipher '!DHE:PSK'


## Server that accepts both normal and PSK ciphers

openssl s_server -key key.pem -cert cert.pem -accept 44330 -www -psk fcc56e7668194a4775e5b36e2735551a


## Session Stealing Attack (FAILED)

1. We assume the victim client first connects to the TLS server of the adversary. This is was our WolfSSL client
   currently does. The client will store the session information so it can do a session resumption handshake when
   it again connects to the server.

2. When the victim client connects to a legitimate server, our MitM will reply with a ServerHello (since the client
   must receive this as first message from the server).

3. The MitM will now send a ClientHello containing a SessionID that refers to the stored session with the _adversary's_
   server. The victim client will now load this session, including the corresponding master secret, and continue
   a session resumption handshake. Note that the session is only loaded properly when SNI is disabled. When SNI is
   enabled the client will mark itself as a server on reception of a ClientHello, and as a result it will not load
   the stored session because the "role" doesn't match anymore. As can be seen here `src/ssl.c:GetSession`:

		if (XMEMCMP(current->sessionID, id, ID_LEN) == 0 &&
		        current->side == ssl->options.side) {
		    WOLFSSL_MSG("Found a session match");

   So the client has now loaded a masterSecret that we know! Because this masterSecret was used when connecting
   to the adversary's server.

   Note that the client will use the stored session, even when the WolfSSL client didn't explicitly load a session
   that should be resumed for this connection.

4. The big problem is that on reception of a ClientHello, the client will generate a random serverRandom (because this
   function is normally only executed on a server). And this new serverRandom is never revealed. So although we know
   the masterSecret and clientRandom, we don't know the serverRandom, so we don't know the derived session keys.

   We got close. Even overwrote the masterSecret. But we can't complete the connection because serverRandom is unknown.

   Before commit 8d8fca67c3 the RNG can silently fail... so we could theoretically rely on that failing...


## General Questions

How do clients manage when to use a stored session for a connection? Could there be vulnerabilities in this code?
Is is based on the domain/IP?

