/*
 * Starts a child that computes for about 0.2 s, then execs this program
 * again, which computes as long in another function, so that a recording
 * of it has the child before and after its exec.
 *
 * Build: cc -O2 -o spawns spawns.c
 * Usage: spawns
 */
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WORK_NS 200000000L

static volatile unsigned long sink;

static long elapsed_ns(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000000000L + now.tv_nsec - start->tv_nsec;
}

/* The two do different work, so that the compiler does not fold them into
 * one function. */
__attribute__((noinline)) static void before_exec(void)
{
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);
	while (elapsed_ns(&start) < WORK_NS)
		for (int i = 0; i < 100000; i++)
			sink += i;
}

__attribute__((noinline)) static void after_exec(void)
{
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);
	while (elapsed_ns(&start) < WORK_NS)
		for (int i = 0; i < 100000; i++)
			sink ^= i;
}

int main(int argc, char **argv)
{
	int status;
	pid_t child;

	if (argc > 1) {
		after_exec();
		return 0;
	}
	child = fork();
	if (child == 0) {
		before_exec();
		execl(argv[0], argv[0], "exec'd", (char *)NULL);
		_exit(1);
	}
	waitpid(child, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
