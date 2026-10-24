/*
 * Test program with known call paths: spin() does all the work, and
 * from_a() calls it for three times as much work as from_b():
 *   main -> from_a -> spin   about 75% of the CPU time
 *   main -> from_b -> spin   about 25%
 *
 * Build: cc -O2 -fno-omit-frame-pointer -Wl,--build-id -o paths paths.c
 * Usage: paths [rounds]   (each round takes about 8 ms on a 3.5 GHz core)
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

/* GCC sets up no frame in a function that calls nothing, so frame-pointer
 * stacks would skip its caller. The call to keep() makes spin() keep one. */
KEEP uint64_t spin(uint64_t x, uint64_t n)
{
	for (uint64_t i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
	keep(x);
	return x;
}

/* Using the result keeps each call from becoming a jump that drops the
 * caller's frame. */
KEEP uint64_t from_a(uint64_t x)
{
	return spin(x, 3 * WORK) + 1;
}

KEEP uint64_t from_b(uint64_t x)
{
	return spin(x, WORK) + 1;
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
