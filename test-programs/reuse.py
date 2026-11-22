"""
Python test program of functions that take one another's place: it makes
gen_0() to gen_5() one at a time, and frees each before it makes the next,
so CPython keeps the code of each where it kept that of the one before. Each
runs as long as the others, so each should get a sixth of their time.

Usage: python3 reuse.py [milliseconds]   (how long each function runs, 50)
"""
import gc
import sys
import time

FUNCTIONS = 6


def make(name):
    scope = {"monotonic": time.monotonic}
    exec(
        f"def {name}(seconds):\n"
        "    end = monotonic() + seconds\n"
        "    total = 0\n"
        "    while monotonic() < end:\n"
        "        for i in range(1000):\n"
        "            total += i * i\n"
        "    return total\n",
        scope,
    )
    return scope[name]


seconds = (int(sys.argv[1]) if len(sys.argv) > 1 else 50) / 1000
for i in range(FUNCTIONS):
    function = make(f"gen_{i}")
    function(seconds)
    del function
    gc.collect()
