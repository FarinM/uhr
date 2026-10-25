/*
 * Test program whose threads wait in known ways:
 *   holder    takes a lock and computes while holding it
 *   locker    waits for that lock in wait_for_lock()
 *   napper    sleeps in nap() for as long
 *   spin_a    and spin_b compute for half as long each, on one CPU, so
 *   spin_b    each waits for the other to be preempted
 *   main      waits in pthread_join()
 * So holder computes, spin_a and spin_b are about half the time runnable,
 * and locker, napper and main are blocked.
 *
 * Build: cc -O2 -pthread -fno-omit-frame-pointer -Wl,--build-id -o waits waits.c
 * Usage: waits [ms]   (how long holder computes, default 200)
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#if defined(__clang__)
#define KEEP __attribute__((noinline))
#else
#define KEEP __attribute__((noipa))
#endif

static uint64_t work_ns = 200000000;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static sem_t locked;
static cpu_set_t one_cpu;

static uint64_t now(clockid_t clock)
{
	struct timespec ts;
	clock_gettime(clock, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
}

/* Computes until the thread has used `ns` more CPU time. */
KEEP uint64_t compute(uint64_t ns)
{
	uint64_t until = now(CLOCK_THREAD_CPUTIME_ID) + ns;
	uint64_t x = 88172645463325252ull;
	while (now(CLOCK_THREAD_CPUTIME_ID) < until) {
		for (int i = 0; i < 10000; i++) {
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
		}
	}
	return x;
}

KEEP void wait_for_lock(void)
{
	pthread_mutex_lock(&lock);
	pthread_mutex_unlock(&lock);
}

KEEP void nap(uint64_t ns)
{
	uint64_t until = now(CLOCK_MONOTONIC) + ns;
	struct timespec ts = { 0, 10000000 };
	while (now(CLOCK_MONOTONIC) < until)
		nanosleep(&ts, NULL);
}

static void *holder(void *arg)
{
	(void)arg;
	pthread_setname_np(pthread_self(), "holder");
	pthread_mutex_lock(&lock);
	sem_post(&locked);
	uint64_t x = compute(work_ns);
	pthread_mutex_unlock(&lock);
	return (void *)(uintptr_t)x;
}

static void *locker(void *arg)
{
	(void)arg;
	pthread_setname_np(pthread_self(), "locker");
	sem_wait(&locked);
	wait_for_lock();
	return NULL;
}

static void *napper(void *arg)
{
	(void)arg;
	pthread_setname_np(pthread_self(), "napper");
	nap(work_ns);
	return NULL;
}

static void *spinner(void *name)
{
	pthread_setname_np(pthread_self(), name);
	pthread_setaffinity_np(pthread_self(), sizeof(one_cpu), &one_cpu);
	return (void *)(uintptr_t)compute(work_ns / 2);
}

int main(int argc, char **argv)
{
	if (argc > 1)
		work_ns = strtoull(argv[1], NULL, 10) * 1000000;
	sem_init(&locked, 0, 0);
	CPU_ZERO(&one_cpu);
	CPU_SET(sched_getcpu(), &one_cpu);

	pthread_t threads[5];
	if (pthread_create(&threads[0], NULL, holder, NULL) != 0 ||
	    pthread_create(&threads[1], NULL, locker, NULL) != 0 ||
	    pthread_create(&threads[2], NULL, napper, NULL) != 0 ||
	    pthread_create(&threads[3], NULL, spinner, "spin_a") != 0 ||
	    pthread_create(&threads[4], NULL, spinner, "spin_b") != 0) {
		fprintf(stderr, "pthread_create failed\n");
		return 1;
	}
	uintptr_t x = 0;
	for (int i = 0; i < 5; i++) {
		void *result;
		pthread_join(threads[i], &result);
		x ^= (uintptr_t)result;
	}
	printf("%llu\n", (unsigned long long)x);
	return 0;
}
