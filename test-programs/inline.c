/*
 * Test program with known inlined calls: mix() does all the work, and is
 * inlined into from_a(), which asks for three times as much work as
 * from_b(), where it is inlined too:
 *   main -> from_a -> mix (inlined)   about 75% of the CPU time
 *   main -> from_b -> mix (inlined)   about 25%
 * Without debug info a profile can only credit the time to from_a and
 * from_b, since mix has no machine code of its own.
 *
 * Build: cc -O2 -g -fno-omit-frame-pointer -Wl,--build-id -o inline inline.c
 * Usage: inline [rounds]   (each round takes about 8 ms on a 3.5 GHz core)
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

static inline __attribute__((always_inline)) uint64_t mix(uint64_t x, uint64_t n)
{
	for (uint64_t i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
	return x;
}

/* The call to keep() gives each caller a stack frame, and using the result
 * keeps it from becoming a jump that drops the frame. */
KEEP uint64_t from_a(uint64_t x)
{
	x = mix(x, 3 * WORK);
	keep(x);
	return x + 1;
}

KEEP uint64_t from_b(uint64_t x)
{
	x = mix(x, WORK);
	keep(x);
	return x + 1;
}

int main(int argc, char **argv)
{
	uint64_t rounds = argc > 1 ? strtoull(argv[1], NULL, 10) : 200;
	uint64_t x = 88172645463325252ull;

	/* Interleaving keeps the split stable when the CPU frequency changes
	 * during the run. */
	for (uint64_t r = 0; r < rounds; r++) {
		x = from_a(x);
		x = from_b(x);
	}
	printf("%llu\n", (unsigned long long)x);
	return 0;
}
