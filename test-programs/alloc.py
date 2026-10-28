# Grows the heap by a known amount in one function, and churns a little in
# another: build() makes 40000 buffers of a page each, about 160 MiB. It
# computes first, as a profiler that finds the interpreter from its first
# samples reads no Python frames before.
#
# Usage: python3 alloc.py

import time


def spin(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        pass


def build(n):
    return [bytearray(4096) for _ in range(n)]


def churn():
    return [str(i) for i in range(20000)]


def main():
    spin(0.3)
    kept = build(40000)
    for _ in range(20):
        churn()
    return len(kept)


main()
