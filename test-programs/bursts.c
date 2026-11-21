/*
 * Computes in bursts of about 0.2 ms between sleeps of 0.5 ms, as an event
 * loop runs between waits, for about 1.5 s: a sampler that polls finds it
 * asleep more often than computing, but all its CPU time is in burst().
 *
 * Build: cc -O2 -o bursts bursts.c
 * Usage: bursts
 */
#include <time.h>
#include <unistd.h>

#define BURST_NS 200000L
#define ROUNDS 2000

static volatile unsigned long sink;

static long elapsed_ns(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000000000L + now.tv_nsec - start->tv_nsec;
}

__attribute__((noinline)) static void burst(void)
{
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);
	while (elapsed_ns(&start) < BURST_NS)
		for (int i = 0; i < 1000; i++)
			sink += i;
}

int main(void)
{
	for (int round = 0; round < ROUNDS; round++) {
		burst();
		usleep(500);
	}
	return 0;
}
