- A minor hack (found in the enclosed `hostapd-tls-server.patch`) was applied to the `malloc_align.py` of the diff-tool to remove allocations of size `0x40` which polluted the malloc logs with 10k+ allocations which prevented diff tool from completing computation in reasonable time. 

- We did not this target with alternating certificates in the bootstrap flows as with other TLS implementations tested.
