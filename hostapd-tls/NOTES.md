# `src/tls/tlsv1_server_handshake.c` function `tlsv1_server_handshake`

On a failure, the state is set to `FAILURE`, and a counter is increased.

    ..

    os_free(in_msg);
    if (conn->alert_level) {
	    if (conn->state == FAILED) {
		    /* Avoid alert loops */
		    wpa_printf(MSG_DEBUG, "TLSv1: Drop alert loop");
		    os_free(msg);
		    return NULL;
	    }
	    conn->state = FAILED;
	    os_free(msg);
	    msg = tlsv1_server_send_alert(conn, conn->alert_level,
				          conn->alert_description,
				          out_len);
	    conn->write_alerts++;
    }

    ...


# The client doesn't have such a counter

    failed:
	    os_free(in_msg);
	    if (conn->alert_level) {
		    wpabuf_free(conn->partial_input);
		    conn->partial_input = NULL;
		    conn->state = FAILED;
		    os_free(msg);
		    msg = tlsv1_client_send_alert(conn, conn->alert_level,
					          conn->alert_description,
					          out_len);
	    }

As a result tracking the state of the client is easier. But for the server we will
need traint tracking to avoid this state update in the server.


# Notes

Future work can test using a full alphabet where client packets are also sent towards
clients (and server packets towards servers). But this has the following problems:

- ClientKeyExchange cannot currently be sent by the TLS Harness when acting as a server.

- Hostap doesn't support HeartbeatRequest or HeartbeatResponse. These are immediately dropped,
  and cause the record encryption between the client and learner to desynchronize.

Additionally, using more packets causes a seemingly infinite loop where the client keeps
replying using Alert2.10 messages ("unexpected message").

