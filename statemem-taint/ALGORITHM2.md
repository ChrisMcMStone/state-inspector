For each watchpoint (WP, WP-SIZE), we first attempt to locate the instruction responsible for causing the WP hit. This will be the instruction (START) preceeding that at the reported PC value.

From START, we simulate its execution in order to obtain its memory accesses (ACCESSES). For each of the ACCESSES, we mark the memory and registers as tainted. We also symbolise the memory region (WP, WP-SIZE) and ranges in our ASSUMED-STATE-MEMORY.

We step forwards until we encounter a branch (CONDITIONAL) whose decision is influenced by the taint propagated from the ACCESSES caused by the WP hit.

At this point, we follow the branch and calculate the PATH-CONSTRAINTS. We compute a model for each of the branch directions TAKEN in the concrete trace and NOT-TAKEN (the other possible branch target). These models tell us the expected value for WP to reach each branch target; they also tell us if other ASSUMED-STATE-MEMORY has been constrained to reach either branch from START.

We compute the MERGE point of the two branch targets.

For each of TAKEN and NOT-TAKEN models, we run again from START to CONDITIONAL. We then run from CONDITIONAL to MERGE. For each instruction processed before MERGE, we check the memory accesses (COND-STORES, COND-LOADS). If any of the COND-STORES are in ASSUMED-STATE-MEMORY, then we have detected a CONDITIONAL dependent write to ASSUMED-STATE-MEMORY, we report it. For all other COND-STORES and COND-LOADS we taint the accessed memory (COND-DEP-MEMORY). If we reach MERGE, we continue to process instructions until we deplete the execution WINDOW. For each instruction processed we check the memory stores (MERGE-STORES), if any of these stores writes to ASSUMED-STATE-MEMORY and is tainted by COND-DEP-MEMORY, then we assume the store was influenced by CONDITIONAL, and we report it.

If we report a CONDITIONAL dependent write to ASSUMED-STATE-MEMORY, then we report the symbolic model on WP and ASSUMED-STATE-MEMORY.
