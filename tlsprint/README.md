# Containerised TLS SUTs


The `learner_docker.sh` script in this directory automatically pulls a specified TLS image from [here](https://hub.docker.com/u/tlsprint) and launches statelearner against it.

To set up, modify the hardcoded paths in the script to the appropraiate paths on your filesystem, and launch with:

```
./learner_docker.sh tlsprint/openssl:1.1.1g tls-template-docker.properties
```

Where `tlsprint/openssl:1.1.g` can be replaced with any `tlsprint/TAGNAME` taken from the [openssl repo](https://hub.docker.com/r/tlsprint/openssl/tags) or [mbedtls repo](https://hub.docker.com/r/tlsprint/mbedtls/tags).

The `tls-template-docker.properties` is included in this directory. The script will automatically appends the `bin_path` and `output_dir` parameters, so these should be left out. 


TODO: add `app_name` support to .properties once ptrace/statemem syscall parameters implemented for mbedtls.
