- I think the individual directories contain an old/incorrect *.properties file.
- The directories ending on `without-taint-analysis` contain the correct *.properties file.

Likely parameters used during tests:
- `ptrace_attach_delay=200`
- `reset_inputs= ASSOC(RSNE=cc)`

The `unpatched-alphabet-15-without-taint-analysis` test was executed under commit
`9df65065e0ca08b8df49e00cdfad087d2c99a223` to have a proper comparison to the tests
done with taint analysis.

