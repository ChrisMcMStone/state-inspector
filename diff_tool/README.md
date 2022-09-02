### Locating state memory

`diff_tool.py` locates candidate state memory by making the following assumptions about how state memory behaves and the values it will contain:

- The memory addresses are written to in at least one state transition (or sequential snapshots)
- They have the same values in every equivalent (defined by I/O seq and type(read or write)) snapshot. (Currently, we make an exception for the first snapshot, as here the memory is likely to be uninitialized and hence have an undefined value)
- The values do not contain pointers to other locations in memory.
