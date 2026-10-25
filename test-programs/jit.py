"""
Python test program with a known split: work() calls hot(), which does four
times the work of warm(), so hot() should get about 80% of the CPU time and
warm() about 20%, all under work().

Usage: python3 jit.py [rounds]   (each round takes about 10 ms)
"""
import sys


def hot(n):
    total = 0
    for i in range(n):
        total += i * i
    return total


def warm(n):
    total = 0
    for i in range(n):
        total += i * i
    return total


def work(rounds):
    return sum(hot(320000) + warm(80000) for _ in range(rounds))


work(int(sys.argv[1]) if len(sys.argv) > 1 else 50)
