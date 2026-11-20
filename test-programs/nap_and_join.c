/*
 * The main thread waits for about 0.6 s: it sleeps, then joins a thread
 * that computes for as long, so a recording shows where it waited.
 *
 * Build: cc -O2 -pthread -o nap_and_join nap_and_join.c
 * Usage: nap_and_join
 */
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define WAIT_NS 300000000L

static volatile unsigned long sink;

static long elapsed_ns(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000000000L + now.tv_nsec - start->tv_nsec;
}

static void *compute(void *unused)
{
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);
	while (elapsed_ns(&start) < WAIT_NS)
		for (int i = 0; i < 100000; i++)
			sink += i;
	return unused;
}

/* Each counts after its call, so that the call is not its last and keeps
 * its frame on the stack. */
__attribute__((noinline)) static void nap(void)
{
	usleep(WAIT_NS / 1000);
	sink++;
}

__attribute__((noinline)) static void join(pthread_t thread)
{
	pthread_join(thread, NULL);
	sink++;
}

int main(void)
{
	pthread_t computer;

	nap();
	pthread_create(&computer, NULL, compute, NULL);
	join(computer);
	return 0;
}
