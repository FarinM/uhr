/*
 * Grows its heap by a known amount, with a child process that grows its
 * own, then keeps it all for a while.
 *
 * Build: cc -O2 -o grow grow.c
 * Usage: grow [MiB] [child MiB] [ms to keep it]   (128, 64 and 300 by default)
 */
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define STEP (8 << 20)

/*
 * Writes a byte to each page, so that every page is resident. Through a
 * volatile pointer, as a compiler may drop writes nothing reads, and in a
 * function of its own, which the page faults are then in.
 */
__attribute__((noinline)) static void touch(volatile char *memory, long bytes)
{
	long page = sysconf(_SC_PAGESIZE);
	for (long at = 0; at < bytes; at += page)
		memory[at] = 1;
}

static void grow(long mib)
{
	for (long done = 0; done < mib << 20; done += STEP) {
		touch(malloc(STEP), STEP);
		usleep(20000);
	}
}

int main(int argc, char **argv)
{
	long mib = argc > 1 ? atol(argv[1]) : 128;
	long child_mib = argc > 2 ? atol(argv[2]) : 64;
	long keep_ms = argc > 3 ? atol(argv[3]) : 300;

	pid_t child = -1;
	if (child_mib > 0) {
		child = fork();
		if (child == 0) {
			grow(child_mib);
			usleep(keep_ms * 1000);
			_exit(0);
		}
	}
	grow(mib);
	usleep(keep_ms * 1000);
	if (child > 0)
		waitpid(child, NULL, 0);
	return 0;
}
