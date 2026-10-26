"""
Python test program whose stacks go from Python into C and back: sort()
has libc's qsort() sort numbers, with compare() as the comparison, which
spins for a while each time. sort() first calls itself `depth` times.

Usage: python3 callback.py [rounds] [depth]   (each round takes about 5 ms)
"""
import ctypes
import sys

libc = ctypes.CDLL(None)
Compare = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)
)


def compare(a, b):
    total = 0
    for i in range(2000):
        total += i
    return a[0] - b[0]


def sort(rounds, depth):
    if depth > 0:
        return sort(rounds, depth - 1)
    callback = Compare(compare)
    for _ in range(rounds):
        numbers = (ctypes.c_int * 64)(*range(64, 0, -1))
        libc.qsort(numbers, len(numbers), ctypes.sizeof(ctypes.c_int), callback)


rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 20
depth = int(sys.argv[2]) if len(sys.argv) > 2 else 0
sort(rounds, depth)
