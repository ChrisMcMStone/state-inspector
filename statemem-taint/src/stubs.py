import triton


class Exited(Exception):
    def __init__(self, code):
        self.code = code


    def __repr__(self):
        return "Exited({})".format(self.code)


    def __str__(self):
        return "exit({}) called".format(self.code)


class NeedsInput(Exception):
    def __init__(self, name):
        self.name = name


    def __repr__(self):
        return "NeedsInput({:?})".format(self.name)


    def __str__(self):
        return "{} called; needs input".format(self.name)


def do_nothing(_ctx):
    return 0


def debug(name, logger=None):
    def run(_ctx):
        if logger:
            logger.debug("{} called".format(name))
    return run


def printf(_ctx):
    return 0


def exit(ctx):
    raise Exited(ctx.getConcreteRegisterValue(ctx.registers.rdi))


def needs_input(name, logger=None):
    def run(_ctx):
        if logger:
            logger.debug("{} called".format(name))
        raise NeedsInput(name)
    return run

def strncmp(_ctx):
    return 1

def send(_ctx):
    # Assume send returns the number of bytes corresponding to buffer size store in $EDX
    # Assume arch == triton.ARCH.X86
    return _ctx.getConcreteMemoryValue(triton.MemoryAccess(
                _ctx.getConcreteRegisterValue(_ctx.registers.edx), triton.CPUSIZE.DWORD))
