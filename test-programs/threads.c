/*
 * Multithreaded test program with known behavior:
 *   heavy    computes, and does twice the work of light
 *   light    computes
 *   sleeper  blocks in read() until both are done
 *   main     blocks in pthread_join()
 * So heavy should get about 2/3 of the CPU time and light about 1/3, while
 * sleeper and main mostly wait. How much of their lives heavy and light
 * spend on a CPU depends on what else the machine runs, so each thread
 * measures its own CPU and elapsed time, and the program prints them:
 *   thread <name> cpu_ns <n> wall_ns <n>
 *
 * Build: cc -O2 -pthread -fno-omit-frame-pointer -Wl,--build-id -o threads threads.c
 * Usage: threads [rounds]   (heavy takes about 8 ms per round on a 3.5 GHz core)
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#if defined(__clang__)
#define KEEP __attribute__((noinline))
#else
#define KEEP __attribute__((noipa))
#endif

#define WORK 2000000

static uint64_t rounds = 200;
static int done_pipe[2];

struct timing {
	const char *name;
	uint64_t cpu_ns;
	uint64_t wall_ns;
};

enum { HEAVY, LIGHT, SLEEPER, MAIN, THREADS };
static struct timing timings[THREADS] = {
	{ "heavy", 0, 0 }, { "light", 0, 0 }, { "sleeper", 0, 0 }, { "threads", 0, 0 },
};

static uint64_t now(clockid_t clock)
{
	struct timespec ts;
	clock_gettime(clock, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
}

static void finish(int thread, uint64_t started)
{
	timings[thread].cpu_ns = now(CLOCK_THREAD_CPUTIME_ID);
	timings[thread].wall_ns = now(CLOCK_MONOTONIC) - started;
}

KEEP uint64_t heavy_work(uint64_t x, uint64_t n)
{
	for (uint64_t i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
	return x;
}

KEEP uint64_t light_work(uint64_t x, uint64_t n)
{
	for (uint64_t i = 0; i < n; i++) {
		x ^= x << 5;
		x ^= x >> 9;
		x ^= x << 21;
	}
	return x;
}

static void *heavy(void *arg)
{
	uint64_t started = now(CLOCK_MONOTONIC);
	pthread_setname_np(pthread_self(), timings[HEAVY].name);
	uint64_t x = (uintptr_t)arg;
	for (uint64_t r = 0; r < rounds; r++)
		x = heavy_work(x, 2 * WORK);
	finish(HEAVY, started);
	return (void *)(uintptr_t)x;
}

static void *light(void *arg)
{
	uint64_t started = now(CLOCK_MONOTONIC);
	pthread_setname_np(pthread_self(), timings[LIGHT].name);
	uint64_t x = (uintptr_t)arg;
	for (uint64_t r = 0; r < rounds; r++)
		x = light_work(x, WORK);
	finish(LIGHT, started);
	return (void *)(uintptr_t)x;
}

static void *sleeper(void *arg)
{
	(void)arg;
	uint64_t started = now(CLOCK_MONOTONIC);
	pthread_setname_np(pthread_self(), timings[SLEEPER].name);
	char byte;
	/* Returns 0 once main closes the write end. */
	while (read(done_pipe[0], &byte, 1) > 0)
		;
	finish(SLEEPER, started);
	return NULL;
}

int main(int argc, char **argv)
{
	uint64_t started = now(CLOCK_MONOTONIC);
	if (argc > 1)
		rounds = strtoull(argv[1], NULL, 10);
	if (pipe(done_pipe) != 0) {
		perror("pipe");
		return 1;
	}

	pthread_t threads[3];
	void *(*bodies[3])(void *) = { heavy, light, sleeper };
	for (int i = 0; i < 3; i++) {
		if (pthread_create(&threads[i], NULL, bodies[i],
				   (void *)(uintptr_t)(88172645463325252ull + i)) != 0) {
			fprintf(stderr, "pthread_create failed\n");
			return 1;
		}
	}

	void *heavy_result, *light_result;
	pthread_join(threads[HEAVY], &heavy_result);
	pthread_join(threads[LIGHT], &light_result);
	close(done_pipe[1]);
	pthread_join(threads[SLEEPER], NULL);
	finish(MAIN, started);

	printf("%llu\n", (unsigned long long)((uintptr_t)heavy_result ^ (uintptr_t)light_result));
	for (int i = 0; i < THREADS; i++)
		printf("thread %s cpu_ns %llu wall_ns %llu\n", timings[i].name,
		       (unsigned long long)timings[i].cpu_ns, (unsigned long long)timings[i].wall_ns);
	return 0;
}
