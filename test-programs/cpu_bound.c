/*
 * CPU-bound test program with a known split: hot() does four times the work
 * of warm(), so it should get about 80% of the CPU time and warm() about 20%.
 *
 * Build: cc -O2 -fno-omit-frame-pointer -Wl,--build-id -o cpu_bound cpu_bound.c
 * Usage: cpu_bound [rounds]   (each round takes about 8 ms on a 3.5 GHz core)
 *
 * GCC gives hot() and warm() no frame setup because they don't use the stack,
 * so frame-pointer stacks skip main(). Clang keeps the frame.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Inlining, cloning or merging the two functions would change which names
 * the samples land on. */
#if defined(__clang__)
#define KEEP __attribute__((noinline))
#else
#define KEEP __attribute__((noipa))
#endif

#define WORK 1000000

/* Each iteration is a chain of dependent shifts and xors, so the cost per
 * iteration is the same in both functions and can't be optimized away. */
KEEP uint64_t hot(uint64_t x, uint64_t n)
{
	for (uint64_t i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
	return x;
}

KEEP uint64_t warm(uint64_t x, uint64_t n)
{
	for (uint64_t i = 0; i < n; i++) {
		x ^= x << 5;
		x ^= x >> 9;
		x ^= x << 21;
	}
	return x;
}

int main(int argc, char **argv)
{
	uint64_t rounds = argc > 1 ? strtoull(argv[1], NULL, 10) : 200;
	uint64_t x = 88172645463325252ull;

	/* Interleaving keeps the split stable when the CPU frequency changes
	 * during the run. */
	for (uint64_t r = 0; r < rounds; r++) {
		x = hot(x, 4 * WORK);
		x = warm(x, WORK);
	}
	printf("%llu\n", (unsigned long long)x);
	return 0;
}
