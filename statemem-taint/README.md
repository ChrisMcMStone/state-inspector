# statemem-taint

First patch Triton using the patch in `triton-python-callback-lambda-fix.patch`.

Build for python 3.6:

```
cmake -B build -DPYTHON36=true
```

**Requirements:** We build our analysis upon Triton; see the corresponding [README](Triton/README.md) for installation instructions. We also depend upon IDA Pro.

## Overview

The purpose of this analysis component is to verify whether a piece of posited state-memory is indeed relevant to state, to the extent that it's value affects the control flow of the main binary<sup>[1](#myfootnote1)</sup>

### Testing scenario

We will execute this process when we reach the following scenario:

- We have a snapshot `Sx` for a state in the protocol which we want to classify via it's memory. We extract the state-memory `smemx` from `Sx` using our set of identified candidate state-memory regions. 
- Given a set of other state classifications in the form of `cls = [smem1, smem2, ...]`, we compare `smemx` with each element of `cls`. We find that `smemx` is equal to an element within `cls` within a given threshold `T` (i.e. it is mostly the same, the the exception of say 1 or 2 mem regions, which we call `tmem`.) Outside of this threshold, we would automatically consider it a different state. 
- Each mem region in `mem` we test to verify whether is has influence on the programs control flow using the below procedure.

### Test process

- Given a set of memory addresses `tmem`, we set read watchpoints at each of these using [ptrace](https://github.com/ChrisMcMStone/greyboxstatelearning/tree/master/ptrace-statemem).
- Each time a watchpoint is hit, we dump the execution state to file.
- For each of these execution states, we perform a state transfer to our dynamic analysis engine Triton. This, along with the analysis is implemented [here](https://github.com/ChrisMcMStone/greyboxstatelearning/blob/master/statemem-taint/src/seqv.py). 
- Using dynamic taint tracking, from the point of the watchpoint read hit, and for a given *code window* size, we:
	* Track execution until the first branch (end of the basic block enclosing the read). If branch is local, we record the taint dependency information (tainted or not). If the branch is inteprocedural (e.g. a function call), we abort. (**TODO: check taint of all branches in window by also tainting the interprocedural returns**). 
 	* For all tainted local branches, we verify whether the target branch can be reached via any other control flow paths. We expect target branches reached via reads of legitimate state memory to only be reachable in this way. Those we find that are reachable via other paths, we additionally verify that no writes to state memory are performed. 


## False positives

Below are documented examples of false-postive state memory which:
- We posit is state memory from our happy flow diffing.
- Falls within the difference-threshold for otherwise equivalent state snapshot, hence is flagged for taint testing.
- (Wrongly) detected as impacting state-control flow by the tainter.

### OpenSSL

### Hostapd

<br/><br/><br/>


<a name="myfootnote1">1</a>: We assume that protocol state logic will not be implemented in shared libraries. 


## Algorithm

1. Locate read corresponding to watchpoint hit
2. Locate basic block enclosing the watchpoint hit (i.e., the instruction prior to the hit); we must do this as the hit will be the instruction following the hit.
    - This may not be possible if the hit was caused by an instruction that modifies control flow (i.e., the next instruction is a jump target of a read).
3. We taint all load accesses, store accesses and written registers of the read instruction
4. We follow linear execution until a branching instruction is encountered:
    - For local control flow (i.e., a jump) we report a dependency iff the branch is tainted
    - For non-local control flow (i.e., a call or HLT) we abort the analysis

### Basic analysis

1. If there is a dependency, we perform CFG reconstruction
2. We then compute the immediate dominators of the CFG of the function containing the watchpoint hit PC
3. We get the idoms of the branch target reported via the dependency
4. We check if the block containing the read dominates the block of the branch target, if it does we say the memory influences the state

### Extended analysis

We check if following the branch target, for a given window of instructions, any loads or stores performed are associated with the assumed state memory, if they are we assume the memory influences the state

