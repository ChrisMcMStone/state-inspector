

## Inputs:

- `meta_logs` = List of JSON snapshot meta-data logs (matches abstract INPUT & OUTPUT sequences to file path of snapshot files, timestamps, session_ids e.g. `/meta_1.log`) 
- `mem_maps` = Proc mem-maps log (e.g., `mem_maps1.log`)
- `malloc_logs` = file names of each malloc log which tracks allocations and frees with a timestamp. Session ID in file name (e.g., `malloc1.log`)

#### Other Inputs (non-essential for basic algorithm)

- List of abstract strings indicated protocol termination (e.g. `ConnClosed`)


### Algorithm:

#### Set up

1. Group snapshot files from `meta_logs` by those with equivalent input & output sequences, `grouped_snaps`
2. Extract the heap base address `heap_base`, and the ranges of mapped memory `mapped_ranges` from `mem_maps`.
3. Chose a representative mallog log `rep_log` (usually the first happy flow log which is `malloc1.log`).

#### Main

1. Initialise `malloc_dict[key=sessionID]` -> list of malloc objects(pc, size, sessID/mallog log, etc), and populate with the `rep_log` mallocs.
2. for each group of equivalent snapshots `gs` in `grouped_snaps`.
    - populate/update the `malloc_dict` for each snapshot's session ID, up until the timestamp of each snapshot
    - build `mappings` which is the mapping of equivalent allocations for the session ids for each snapshot in `gs`
    - For each mapped allocation `m` in `mappings`, and for each offset `o` in `m`:
        * check the value `v` at the offset is equivalent in all snapshots in the current round
        * if the offset has been previously flagged as equal in other rounds, ensure it also contains the same value in all the snapshots of the current round. If not, remove it
  
