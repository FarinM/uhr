/*
 * Grows its heap by a known amount, with a child process that grows its
 * own, then keeps it all for a while.
 *
 * Build: cc -O2 -o grow grow.c
 * Usage: grow [MiB] [child MiB] [ms to keep it]   (128, 64 and 300 by default)
 */
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define STEP (8 << 20)

/* Touched, so every page is resident. */
static void grow(long mib)
{
	for (long done = 0; done < mib << 20; done += STEP) {
		memset(malloc(STEP), 1, STEP);
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
