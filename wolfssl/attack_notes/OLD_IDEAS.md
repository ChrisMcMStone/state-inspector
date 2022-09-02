# Old Server Attack Idea

## Recovering GCM Authentication Key (FAILED)

So we by sending a ServerHello to the server we can control the serverRandom value. And against static
RSA we can reply a ClientKeyExchange so the server reloads the same keys. This assumes that Extended
Master Secret is disabled (RFC 7627). The problem is that we can't replay an old handshake/connection
because although we can reply the ClientKeyExchange, we cannot replay the Finished message, because
the injected ServerHello to the server causes the Finished hash to join.

As an alternative attack, the basic idea was to make the server send multiple records encrypted under
the same (key, nonce) pair. That would allow us to recover the authentication key. To make the server
send encrypted records we target a session resumption handshake. Eventually the attack fails because
even then we still cannot make the server send data under the "replayed" keys (because the "replayed"
keys will only be used--I think--after sending/receiving the ChangeCipherSpec).

1. A legitimate (possible the adversary) connects to the target server. This creates a valid session ID.

2. The victim client connects to the server using static RSA. The MitM captures the clientRandom,
   serverRandom, and ClientKeyExchange. We delay handshake messages after this (will continue the
   handshake later).

3. The adversary sends a ClientHello to resume the connection captured in (1). It will use the clientRandom
   captures in (2). The server will reply with a ServerHello, CCS, and encrypted Finished.

4. The adversary sends a ServerHello that overwrites the serverRandom with the one in (2).

5. The adversary replays the ClientHello with the one in (2). The same keys as used in the connection
   by (2) will now be installed. **The problem is that the server will only install keys for decryption.**
   **It will still use the old keys (from the session resumption) to send encrypted replies**. This
   unfortunately will cause the attack to fail.

6. The adversary sends a ChangeCipherSpec. This makes the server encrypt replies again.

7. The adversary sends an ApplicationData frame. The server doesn't expect this message and will send
   an encrypted reply. My hope is that now we would have an encrypted record that was encrypted under
   a (key, nonce) pair that is reused. **But that doesn't work because the "replayed" keys were only**
   **installed for decryption**.

8. With a reused (key, nonce) pair we could recover the GCM authentication key. See for instance
   "Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS".

TODO: **Another assumption that I didn't check is that the nonce is also repeated. That is, it shouldn't**
      **start from a random number**.

