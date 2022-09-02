from intervaltree import IntervalTree, Interval
from typing import DefaultDict, Dict, IO, FrozenSet, List, NamedTuple, Tuple, Union

import triton


# Type aliases
Address = int
Size = int


class LazyLoader(object):
    def __init__(self):
        self.loaded = IntervalTree()
        self.backing = IntervalTree()


    def add_backing(self, address: Address, size: Size, content: bytes):
        self.backing.add(Interval(address, address+size, content))


    def get_backing(self, address: Address, size: Size):
        section = self.backing.at(address).pop()
        offset = address - section.begin
        content = section.data[offset:offset+size]
        if len(content) != size:
            content += (len(content) - size) * b'\x00'
        return content


    def reset_loaded(self):
        self.loaded.clear()


    def is_loaded(self, address: Address, size: Size) -> bool:
        masked = IntervalTree((Interval(address, address+size),))
        for iv in self.loaded.overlap(address, address+size):
            masked.chop(*iv)
        return len(masked) == 0


    def is_backed(self, address: Address, size: Size) -> bool:
        return self.backing.overlaps(address, address+size)


    def store_to_ctx(self, access: triton.MemoryAccess):
        addr = access.getAddress()
        size = access.getSize()
        if not self.is_backed(addr, size):
            return
        self.loaded.add(Interval(addr, addr+size))
        #self.loaded.merge_overlaps()


    def fetch_to_ctx(self, ctx: triton.TritonContext, access: triton.MemoryAccess):
        addr = access.getAddress()
        size = access.getSize()

        # check if we have a backing for this request
        if not self.is_backed(addr, size):
            return


        # check if loaded or partially loaded, compute a mask of ranges to fetch
        masked = IntervalTree((Interval(addr, addr+size),))
        for iv in self.loaded.overlap(addr, addr+size):
            masked.chop(*iv)

        # entire range has already been loaded
        if len(masked) == 0:
            return

        # walk the masked ranges and set the concrete memory
        for iv in masked:
            ctx.setConcreteMemoryAreaValue(iv.begin, self.get_backing(iv.begin, iv.length()))
            # NOTE: this will be added due to the set_loaded callback
            # self.loaded.add(iv)

        #self.loaded.merge_overlaps()


class LoadableSection(object):
    def __init__(self, backing: Union[str, bytes, IO[bytes]], vaddress: Address, vsize: Size, offset: int, size: Size):
        self.backing = backing
        self.vaddress = vaddress
        self.vsize = vsize
        self.offset = offset
        self.size = size
        self.content = None


class DumpLoader(object):
    def __init__(self, arch: triton.ARCH, *sections: LoadableSection):
        self.arch = arch
        self.sections = list(sections)
        self._lazyloader = LazyLoader()


    def load(self) -> triton.TritonContext:
        ctx = triton.TritonContext()
        ctx.setArchitecture(self.arch)
        ctx.setMode(triton.MODE.ALIGNED_MEMORY, True)
        ctx.setMode(triton.MODE.TAINT_THROUGH_POINTERS, True)
        ctx.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

        for section in self.sections:
            if section.content is None:
                content = None
                if isinstance(section.backing, str):
                    with open(section.backing, "rb") as f:
                        f.seek(section.offset, 0)
                        content = f.read(section.size)
                elif isinstance(section.backing, bytes):
                    content = section.backing[section.offset:section.size]
                elif isinstance(section.backing, IO[bytes]):
                    section.backing.seek(section.offset, 0)
                    content = section.backing.read(section.size)
                else:
                    raise ValueError("unsupported section backing: {}".format(type(section.backing)))

                section.content = content

            self._lazyloader.add_backing(section.vaddress, section.vsize, section.content)


        set_conc = lambda _ctx, access, _value: self._lazyloader.store_to_ctx(access)
        get_conc = lambda ctx, access: self._lazyloader.fetch_to_ctx(ctx, access)

        ctx.addCallback(set_conc, triton.CALLBACK.SET_CONCRETE_MEMORY_VALUE)
        ctx.addCallback(get_conc, triton.CALLBACK.GET_CONCRETE_MEMORY_VALUE)

        return ctx


    def reset_loaded(self):
        self._lazyloader.reset_loaded()


class ZzzLoader(object):
    def __init__(self, loader: DumpLoader):
        self.loader = loader
        self._ctx = None


    @property
    def ctx(self) -> triton.TritonContext:
        if self._ctx is None:
            self._ctx = self.loader.load()
        return self._ctx


    def reset(self):
        self._ctx = None


    def reset_backing(self):
        self.loader.reset_loaded()


    def size_of(self, address: int, default: int = 1) -> int:
        return default
