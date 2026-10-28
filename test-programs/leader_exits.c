/*
 * Ends its main thread early, while another thread grows the heap by a
 * known amount and then ends the process. The kernel's files for the
 * process then describe the main thread, which no longer has memory.
 *
 * Build: cc -O2 -pthread -o leader_exits leader_exits.c
 * Usage: leader_exits [MiB]   (128 by default)
 */
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#define STEP (8 << 20)

/*
 * Writes a byte to each page, so that every page is resident. Through a
 * volatile pointer, as a compiler may drop writes nothing reads.
 */
__attribute__((noinline)) static void touch(volatile char *memory, long bytes)
{
	long page = sysconf(_SC_PAGESIZE);
	for (long at = 0; at < bytes; at += page)
		memory[at] = 1;
}

static void *grow(void *arg)
{
	long mib = (long)arg;
	for (long done = 0; done < mib << 20; done += STEP) {
		touch(malloc(STEP), STEP);
		usleep(20000);
	}
	usleep(300000);
	exit(0);
}

int main(int argc, char **argv)
{
	long mib = argc > 1 ? atol(argv[1]) : 128;
	pthread_t thread;
	pthread_create(&thread, NULL, grow, (void *)mib);
	pthread_exit(NULL);
}
