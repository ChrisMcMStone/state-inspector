# OpenSSL

OpenSSL was selected to test this technique, as previous work on learning TLS models ([here](https://usenix.org/system/files/conference/usenixsecurity15/sec15-paper-de-ruiter.pdf)), provides us with both a test harness and many models to compare the results of our technique with. 

Additionally, some of the models in this paper include interesting features not present in other protocol models (like different paths to the same states, cyclical loops in state machines and so on...). This will help us test the robustness of our technique. 

## Set-up

1. Extract `openssl-b2d951e.zip` and run `./config && make` to compile. 
2. Extract `statelearnertls.zip` and run `mvn package shade:shade` to compile (requires maven). 
3. Launch openssl using pre-generated keys and certs in `statelearner/examples/openssl`. Do this in a shell with ASLR disabled (e.g. by running,```setarch `uname -m` -R /bin/bash```). Then launch with:
`./openssl-b2d951e/apps/openssl s_server -key statelearner/examples/openssl/server.key -cert statelearner/examples/openssl/server.crt -CAfile statelearner/examples/openssl/cacert.pem -accept 4500 -www`
4. Using bash script `run.sh` modify file paths accordingly, then `sudo bash ./run.sh happy <session_id>` to execute ssl handshake, and record snapshots, malloc logs etc.
5. In same directory as snapshots, run malloc-based snapshot diff tool, e.g. 
```python3 ../../../diff_tool/malloc_state_diff.py --logs happy_*  --mem-min 0x555555554000 --mem-max 0x555555a24000 --heap-base 0x5555559dc000 --chunk 0```



## State data in OpenSSL

- State memory in (version 1.0.1g) OpenSSL is defined in `ssl_st` struct on line 1114 of `ssl/ssl.h`. The state variable is `int state;`
- For each handshake session, this is initiated at line 2590 of `apps/s_server.c`, where `SSL_new` is the set up function, allocating the memory at line 291 of `ssl/ssl_lib.c`.
- In the snapshots provided, the `ssl_st` is located at `0x32460`, is of size 808 bytes, and the `state` variable is located at `0x324a8`. 

## Progress

Using the memory analysis methods described in the README at the root of this repo, we have already had some success with our new technique. In particular, with the model presented for OpenSSL version 1.0.1g (which contains an example of different routes to same states), I have discovered that part of this model is incorrect. 

![picture](./snapshots/state_machine_usenix.png)

In the model above, states 10 & 15 do not in fact exist, they are the result of a mistake in the test harness configuration. I discovered this after analysing the memory using our proposed method. According to the memory, state 10 is actually state 9, and state 15 is actually state 5. 
I discovered that the reason for this misclassification, is due to a mistake in the test harness. Specifically, I found that the buffer which stores the *sent messages* was not being reset by the test harness. The effect of this was that in the final part of the handshake, when the client harness sends the `Finished` message (which includes a signed hash of all the sent messages), it is rejected by the server because the hash included two ClientHello's. The server expected this hash to only be calculated over the 2nd of these ClientHello's. 
This results in the `Alert` outputs from state 10 & 15, hence they are modelled as different states. 

If one wanted to model the reaction of the server of an incorrect hash in the Finished message, a separate input should be defined which does exactly this.

![picture](./snapshots/state_machine_new.png)

Above I have re-drawn the state machine taking into consideration the new insights from analysing the system's memory. 

