/*
 * Test program with inlined functions that are easy to mix up:
 *   helper   inlined into from_a; a #line directive puts half of its loop
 *            in another file, as generated code does
 *   _helper  a different function, inlined into from_b, whose name differs
 *            only by the leading underscore
 * from_a and from_b do the same amount of work, so helper and _helper each
 * get about half of the CPU time, and helper's two loops a quarter each.
 *
 * Build: cc -O2 -g -fno-omit-frame-pointer -Wl,--build-id -o inline_names inline_names.c
 * Usage: inline_names [rounds]   (each round takes about 8 ms on a 3.5 GHz core)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__clang__)
#define KEEP __attribute__((noinline))
#else
#define KEEP __attribute__((noipa))
#endif

#define WORK 1000000

static volatile uint64_t sink;

KEEP void keep(uint64_t x)
{
	sink = x;
}

static inline __attribute__((always_inline)) uint64_t helper(uint64_t x, uint64_t n)
{
	for (uint64_t i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
#line 1000 "generated.inc"
	for (uint64_t i = 0; i < n; i++) {
		x ^= x << 5;
		x ^= x >> 9;
		x ^= x << 21;
	}
#line 46 "inline_names.c"
	return x;
}

static inline __attribute__((always_inline)) uint64_t _helper(uint64_t x, uint64_t n)
{
	for (uint64_t i = 0; i < 2 * n; i++) {
		x ^= x << 11;
		x ^= x >> 3;
		x ^= x << 19;
	}
	return x;
}

/* The call to keep() gives each caller a stack frame, and using the result
 * keeps it from becoming a jump that drops the frame. */
KEEP uint64_t from_a(uint64_t x)
{
	x = helper(x, WORK);
	keep(x);
	return x + 1;
}

KEEP uint64_t from_b(uint64_t x)
{
	x = _helper(x, WORK);
	keep(x);
	return x + 1;
}

int main(int argc, char **argv)
{
	uint64_t rounds = argc > 1 ? strtoull(argv[1], NULL, 10) : 200;
	uint64_t x = 88172645463325252ull;

	for (uint64_t r = 0; r < rounds; r++) {
		x = from_a(x);
		x = from_b(x);
	}
	printf("%llu\n", (unsigned long long)x);
	return 0;
}
