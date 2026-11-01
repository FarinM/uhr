/*
 * Threads contend for a mutex held only briefly, so that the kernel often
 * wakes one of them while it is still on its way off the CPU.
 *
 * Build: cc -O2 -pthread -o locks locks.c
 * Usage: locks [threads]   (8 by default)
 */
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static volatile long counter;

static void *worker(void *unused)
{
	for (;;) {
		pthread_mutex_lock(&lock);
		for (int i = 0; i < 200; i++)
			counter++;
		pthread_mutex_unlock(&lock);
		for (volatile int i = 0; i < 200; i++)
			;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int threads = argc > 1 ? atoi(argv[1]) : 8;

	for (int i = 0; i < threads; i++) {
		pthread_t thread;

		pthread_create(&thread, NULL, worker, NULL);
	}
	pause();
	return 0;
}
