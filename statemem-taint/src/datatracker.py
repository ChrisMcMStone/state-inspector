from typing import Callable, Dict, Tuple, Union
from lazyloader import ZzzLoader, DumpLoader
from intervaltree import Interval, IntervalTree
from copy import copy

import triton


class DataTrackerLoader(ZzzLoader):
    def __init__(self, loader: DumpLoader, track: Union[None, Tuple[int, int], IntervalTree], ranges: Union[None, IntervalTree] = None):
        super().__init__(loader)
        self.register_callback()
        self.loads = IntervalTree()
        self.suspected_ranges = ranges
        self.should_track = DataTrackerLoader.mk_should_track(track)


    def track_load(self, _ctx: triton.TritonContext, access: triton.MemoryAccess):
        if self.should_track(access):
            addr = access.getAddress()
            size = access.getSize()
            self.loads.add(Interval(addr, addr+size))


    def register_callback(self):
        self.ctx.addCallback(lambda ctx, access: self.track_load(ctx, access),
                             triton.CALLBACK.GET_CONCRETE_MEMORY_VALUE)


    def resolve_loads(self, for_ranges: Union[None, IntervalTree] = None) -> Dict[int, int]:
        # NOTE: initially, suspected ranges will be bytes; we should have a flag
        #       to indicate that we do not know the type initially, and otherwise
        #       should attempt to learn it.
        #
        #       Perhaps we could have two sets of addresses: those that we already
        #       have a suspicion for and those that we don't.
        if self.suspected_ranges is not None:
            t = self.suspected_ranges | self.loads
        else:
            t = copy(self.loads)
        t.split_overlaps()
        minimised = dict()
        starts = list(iv.begin for iv in for_ranges )if for_ranges is not None else None

        for iv in t:
            addr = iv.begin
            if (starts is None or addr in starts) and (self.suspected_ranges is None or addr in self.suspected_ranges):
                size = iv.end-iv.begin
                minimised[addr] = size
        return minimised


    def size_of(self, address: int, default: int = 1) -> int:
        mapping = self.resolve_loads()
        if address in mapping:
            return mapping[address]
        return default


    @staticmethod
    def mk_should_track(ranges: Union[None, Tuple[int, int], IntervalTree]) -> Callable[[triton.MemoryAccess], bool]:
        if ranges is None:
            return lambda _: True
        elif isinstance(ranges, tuple):
            def _should_track(access: triton.MemoryAccess) -> bool:
                address = access.getAddress()
                return address >= ranges[0] and address < ranges[1]
            return _should_track
        else:
            def _should_track(access: triton.MemoryAccess) -> bool:
                address = access.getAddress()
                size = access.getSize()
                return len(ranges.overlap(address, address+size)) != 0
            return _should_track
