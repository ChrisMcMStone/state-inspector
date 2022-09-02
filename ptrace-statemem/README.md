statemem
========

To build only `statemem`, perform the following:

```sh
make statemem/statemem
```

Basic usage will trace read syscalls, and dump heap memory to files prefixed
with `-prefix <dump-prefix>`, or `dump` otherwise, with the formt
`<prefix>_<pid>_<dump-num>.raw`. If `-dump-json` is set, then for each dump
performed a json record will be output to stderr, with the following fields:
`pid`, `syscall_num`, `syscall_name`, `syscall_return`, `dump_path`,
`dump_min_addr`, `dump_max_addr`.
