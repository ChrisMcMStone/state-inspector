
# DH

## Useful links:

WolfSSL DH docs
https://www.wolfssl.com/doxygen/group__Diffie-Hellman.html

comamnds and checks for DH params / ciphersuites
https://thinkerbits.com/tls-and-diffie-hellman-dh-parameters/

old DH attack:
https://link.springer.com/content/pdf/10.1007%2FBFb0052240.pdf
defence:
https://datatracker.ietf.org/doc/html/rfc2785

logjam attack:
https://weakdh.org/
quite weak, relies on 512 bit DH_EXPORT ciphersuites

more modern subgroup attack (similar to logjam):
https://jhalderm.com/pub/papers/subgroup-ndss16.pdf

2015 paper on various common DH weaknesses
https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf

what if different versions of DH allow different parameters? we capture a signed copy of params good for one ciphersuite, then replay these against a client that's chosena  better ciphersuite, can these poarams attack like that?

# Theory

DH section
https://datatracker.ietf.org/doc/html/rfc5246#page-92


When using DH for negotiating a connection it goes as follows:
```


	CLIENT 				SERVER

	 --- ClientHello -->

	 <-- ServerHello ---
	 <-- Certificate ---
	 <-- ServerHelloDone ---

	 <-- ServerKeyExchange --- {DH_G, DH_P, Pub_server, client_random, server_random}signed_server

	 --- ClientKeyExchange --> Pub_client



```
now pub_client and pub_server are used as in DH to derive a pre_master_secret.

Since parameters and server pub are signed they cannot be fiddled with.

However we might be able to inject a malicious ServerKeyExchange TO THE SERVER which will change it's held DH_P and DH_G.

the servers priv is generated randomly and the pub is calculated from the held DH_P and DH_G and the private

```


	CLIENT 				SERVER

	 --- ClientHello -->

	 <-- ServerHello ---
	 <-- Certificate ---
	 <-- ServerHelloDone ---

	 --- ServerKeyExchange --> {DH_G_bad, DH_P_bad, Pub_server_bad, client_random, server_random}forged_sig

	 <-- ServerKeyExchange --- {DH_G_bad, DH_P_bad, Pub_server, client_random, server_random}signed_server

	 --- ClientKeyExchange --> Pub_client



```

(I believe there is a way to overcome the signature problem, see section on Intefering with ServerKeyExchange Signature)

as seen in this diagram we get the ability to send a ServerKeyExchange to the server

when it receives this it:

 - checks the signature is valid
 - copies the G 							ssl->buffers.serverDH_G.buffer
 - copies the P 							ssl->buffers.serverDH_P.buffer
 - copies the public key contained into 	ssl->buffers.serverDH_Pub.buffer

This means our sent ServerKeyExchange overwrites some of its values (P and G) before it generates its own DH key pair

the public key gets overwritten when it calculates its own, we could send a malicious ServerKeyExchange after the server has sent one but we wouldn't control G and P that get sent to the client, we can onyl send one copy of each msg

# What happens in sendServerKeyExchange

Which values get generated in sendServerKeyExchange, this lets us know what we can send before and not be overwritten

```c
if (ssl->buffers.serverDH_P.buffer == NULL ||
    ssl->buffers.serverDH_G.buffer == NULL) {
    ERROR_OUT(NO_DH_PARAMS, exit_sske);
}
```
P and G are checked for non NULL, so they must already be set and not overwritten

then it allocs key

what happens next depends on `ssl->options.dhDoKeyTest`


either it calls setKey or SetCheckKey
```c
ret = wc_DhSetKey(ssl->buffers.serverDH_Key,
                ssl->buffers.serverDH_P.buffer,
                ssl->buffers.serverDH_P.length,
                ssl->buffers.serverDH_G.buffer,
                ssl->buffers.serverDH_G.length);

```

which is:

DhSetKey dh.c:2227

seems to just copy across P G, and perform some prime checks on P if checks are enabled

q is set to null for this func

Then calls DhGenKeyPair:

```c
ret = DhGenKeyPair(ssl, ssl->buffers.serverDH_Key,
                ssl->buffers.serverDH_Priv.buffer,
                (word32*)&ssl->buffers.serverDH_Priv.length,
                ssl->buffers.serverDH_Pub.buffer,
                (word32*)&ssl->buffers.serverDH_Pub.length);
```

wc_DhGenerateKeyPair_Sync dh.c:1316

which generates a completely random priv then uses it to calc a pub with the set P and G

## Verification:

to verify this:

 - check server processes ServerKeyExchange 						[]
 - check G and P are copied across									[]
 - see what checks are conducted on G and P 						[]
 - confirm these are not overwritten when a new key is generated 	[]

At this point we can conduct attacks on G and P

# questions

 - does the server properly check signing of DH params in a serverKex? yes

 - where does it get the cert? (can we send a gratuitous client cert to fool it), yes we can I think

 - how does it verify these parameters are safe given above attacks?

# Intefering with ServerKeyExchange Signature

I think it's possible to forge a signature: this is because when the server receives a ServerkeyExchange it thinks it is a client.

When it checks the signature the key it uses to do so is `ssl->peerRSAKey` (internal.c:123701).

But if it's a server when does it set peerRSAKey? I think that if we send a gratuitous certificate message we can set peerRSAKey.

And if it's a server and not doing client authentication (mutualAuth == 0) it won't verify hostname of peer on the certificate, so any CA signed cert will do :)))

this gives us a vector to forge the signatures on ServerKeyExchanges sent to a server and insert our P and G values

## Where does it get peer cert

upon recieving a certificate message:

DoHandshakeMsgType -> Docertificate

internal.c:12785
```c
ret = ProcessPeerCerts(ssl, input, inOutIdx, size);
```

internal.c:11542

int ProcessPeerCerts(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                     word32 totalSz)
ProcPeerCertArgs  args[1];

allocates buffer in args->certs
11659: copies certs from packet into args->certs

```c
if (args->count == 0 && (ssl->options.mutualAuth ||
     (ssl->options.failNoCert && IsAtLeastTLSv1_3(ssl->version))) &&
                          ssl->options.side == WOLFSSL_SERVER_END) {
    ret = NO_PEER_CERT;
    DoCertFatalAlert(ssl, ret);
}
```

doesn't seem like it cares whether its server / client when processing a cert

12399: decodes RSA public key and copies into ssl->peerRSAkey


10140 in CheckHostName

called from wolfSSL_X509_check_host

```
/*!
    \ingroup Setup

    \brief wolfSSL by default checks the peer certificate for a valid date
    range and a verified signature.  Calling this function before
    wolfSSL_connect() or wolfSSL_accept() will add a domain name check to
    the list of checks to perform.  dn holds the domain name to check
    against the peer certificate when it’s received.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE will be returned if a memory error was encountered.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param dn domain name to check against the peer certificate when received.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    char* domain = (char*) “www.yassl.com”;
    ...

    ret = wolfSSL_check_domain_name(ssl, domain);
    if (ret != SSL_SUCCESS) {
       // failed to enable domain name check
    }
    \endcode

    \sa none
*/
```

Brilliant! 

a client that wants to check domain name must explicitly call wolfSSL_check_domain_name
I doubt servers set it, therefore they will just check for a trusted cert and will veryfiy certificate messages

sanitycheck logic aroiund certificate \/
```c

        case certificate:
            if (ssl->msgsReceived.got_certificate) {
                WOLFSSL_MSG("Duplicate Certificate received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate = 1;

#ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if ( ssl->msgsReceived.got_server_hello == 0) {
                    WOLFSSL_MSG("No ServerHello before Cert");
                    return OUT_OF_ORDER_E;
                }
            }
#endif
#ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                if ( ssl->msgsReceived.got_client_hello == 0) {
                    WOLFSSL_MSG("No ClientHello before Cert");
                    return OUT_OF_ORDER_E;
                }
            }
#endif
            break;
```
looks like there are no checks to see it it actually wants a certificate message, meaning it should got hrough as long as it's after a hello


# What checking is performed on params?

```from RFC
Because TLS allows the server to provide arbitrary DH groups, the
   client should verify that the DH group is of suitable size as defined
   by local policy.  The client SHOULD also verify that the DH public
   exponent appears to be of adequate size.  [KEYSIZ] provides a useful
   guide to the strength of various group sizes.  The server MAY choose
   to assist the client by providing a known group, such as those
   defined in [IKEALG] or [MODP].  These can be verified by simple
   comparison.
```

see attacks linked at top of doc for ideas

code path:

We start off with what happens when we send our malicious ServerKeyExchange

DoServerKeyExchange internal.c:23040

GetDHPublicKey internal.c:22810

This is where keys get copied across into global structs, some checking is performed agains length value in packet, but not checking the contents of the actual values, just the reported length

----------

Later, when a CLientKeyExhcange gets received:


DoClientKeyExchange internal.c:30845

```c
ret = DhAgree(ssl, ssl->buffers.serverDH_Key,
                    ssl->buffers.serverDH_Priv.buffer,
                    ssl->buffers.serverDH_Priv.length,
                    input + args->idx,
                    (word16)args->sigSz,
                    ssl->arrays->preMasterSecret,
                    &ssl->arrays->preMasterSz,
                    ssl->buffers.serverDH_P.buffer,
                    ssl->buffers.serverDH_P.length);
```


DH_agree:

calls wc_DhCheckPubValue on serverDH_Key

wc_DhCheckPubValue dh.c:1568
```c docs:
/**
 * Quick validity check of public key value against prime.
 * Checks are:
 *   - Public key not 0 or 1
 *   - Public key not equal to prime or prime - 1
 *   - Public key not bigger than prime.
 *
 * prime    Big-endian encoding of prime in bytes.
 * primeSz  Size of prime in bytes.
 * pub      Big-endian encoding of public key in bytes.
 * pubSz    Size of public key in bytes.
 */

```

when that func has returned it goes ahead and calls wc_DhAgree

wc_DhAgree dh.c:2060
which appears to have some ifdef guarded checks:

```c
#ifdef WOLFSSL_VALIDATE_FFC_IMPORT
    if (wc_DhCheckPrivKey(key, priv, privSz) != 0) {
        WOLFSSL_MSG("wc_DhAgree wc_DhCheckPrivKey failed");
        return DH_CHECK_PRIV_E;
    }

    if (wc_DhCheckPubKey(key, otherPub, pubSz) != 0) {
        WOLFSSL_MSG("wc_DhAgree wc_DhCheckPubKey failed");
        return DH_CHECK_PUB_E;
    }
#endif
```
after that it does some bitlength checking of the p value

then it does the DH agree algorithm

at some point it checks `/* make sure z is not one (SP800-56A, 5.7.1.1) */`, maybe that stops an attack?

reference to: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf


at this point the secret has been calculated, nothing more is done.