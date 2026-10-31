/*
 * Sleeps again and again on its main thread, in nothing but nanosleep, so
 * that a capture of it ends during a sleep. Another thread computes, but
 * for a quick getppid now and then, so that it ends outside a syscall.
 *
 * Build: cc -O2 -pthread -o naps naps.c
 * Usage: naps [ms]   (how long each sleep is, 100 by default)
 */
#include <pthread.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static void *compute(void *unused)
{
	for (;;) {
		syscall(SYS_getppid);
		for (volatile long i = 0; i < 10000000; i++)
			;
	}
}

int main(int argc, char **argv)
{
	long ms = argc > 1 ? atol(argv[1]) : 100;
	struct timespec nap = {ms / 1000, ms % 1000 * 1000000};
	pthread_t computer;

	pthread_create(&computer, NULL, compute, NULL);
	for (;;)
		nanosleep(&nap, NULL);
}
