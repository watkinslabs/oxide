"""Bounded UART drain after a guest fault marker.

A guest oops is several lines long: the vector/label/err/rip line, an
optional stack-guard BUG line, four GPR lines, and any UAF/corruption
tails. Terminating QEMU on the first byte that matches the fault regex
truncates all of it -- one acceptance run retained exactly
`[FAULT] vec=0000`, four of a sixteen-digit vector, which names neither
the exception nor the faulting address and cannot be re-read later.

The drain keeps pumping until the guest has been quiet for `quiet`
seconds (an unrecoverable fault halts the CPU, so silence is the real
end of the report) or `cap` seconds have elapsed (a fault that keeps
faulting must not hold the run open). Both bounds are deliberate: this
never waits for something to happen, only for something already
happening to finish.
"""

QUIET_SECONDS = 1.0
CAP_SECONDS = 5.0


def drain(pump, clock, quiet=QUIET_SECONDS, cap=CAP_SECONDS):
    """Pump the guest UART until its fault report stops arriving.

    `pump()` captures whatever is available and returns the number of new
    bytes; `clock()` is a monotonic seconds source. Returns the total
    number of bytes captured by the drain.
    """
    started = clock()
    last = started
    total = 0
    while True:
        now = clock()
        if now - started >= cap or now - last >= quiet:
            return total
        count = pump()
        if count:
            total += count
            last = clock()
