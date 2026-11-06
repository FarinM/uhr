/*
 * Test program whose main thread renames its other thread back and forth,
 * to 15 bytes of A and to 15 of B, 100000 times, while that thread calls
 * getppid as fast as it can.
 *
 * Build: cc -O2 -pthread -o renaming renaming.c
 * Usage: renaming
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <unistd.h>

static atomic_int done;

static void *run(void *arg)
{
	while (!atomic_load_explicit(&done, memory_order_relaxed))
		syscall(SYS_getppid);
	return arg;
}

int main(void)
{
	pthread_t thread;
	if (pthread_create(&thread, NULL, run, NULL) != 0)
		return 1;
	for (int i = 0; i < 100000; i++) {
		const char *name = i % 2 ? "BBBBBBBBBBBBBBB" : "AAAAAAAAAAAAAAA";
		if (pthread_setname_np(thread, name) != 0)
			return 1;
	}
	atomic_store(&done, 1);
	pthread_join(thread, NULL);
	return 0;
}
