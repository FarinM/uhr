/*
 * Starts threads one after another, more than a profiler could keep a
 * syscall in flight for each at once, each of which exits at once, then
 * starts one that reads /dev/zero a known number of times. The threads come
 * from clone itself, so that each makes no syscall but its exit, which
 * never returns. A profiler that keeps the syscall each thread is in has to
 * let go of it as the thread exits to still count the last one's.
 *
 * Build: cc -O2 -o thread_exits thread_exits.c
 * Usage: thread_exits [threads] [reads]   (70000 and 1000 by default)
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/futex.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static long reads;
static int zero;
static char stack[64 * 1024] __attribute__((aligned(16)));

static int quit(void *unused)
{
	syscall(SYS_exit, 0);
	return 0;
}

/* Raw syscalls only: the thread has no state of libc's own. */
static int read_zero(void *unused)
{
	char byte;
	for (long i = 0; i < reads; i++)
		if (syscall(SYS_read, zero, &byte, 1) != 1)
			syscall(SYS_exit, 1);
	syscall(SYS_exit, 0);
	return 0;
}

/* Runs `run` on a thread of its own, and waits until it has exited. */
static void run_thread(int (*run)(void *))
{
	static volatile pid_t tid;
	int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
		    CLONE_THREAD | CLONE_SYSVSEM | CLONE_PARENT_SETTID |
		    CLONE_CHILD_CLEARTID;

	if (clone(run, stack + sizeof(stack), flags, NULL, &tid, NULL, &tid) ==
	    -1)
		exit(1);
	/* The kernel clears the id, and wakes its waiters, as it exits. */
	pid_t seen;
	while ((seen = tid) != 0)
		syscall(SYS_futex, &tid, FUTEX_WAIT, seen, NULL, NULL, 0);
}

int main(int argc, char **argv)
{
	long threads = argc > 1 ? atol(argv[1]) : 70000;
	reads = argc > 2 ? atol(argv[2]) : 1000;
	zero = open("/dev/zero", O_RDONLY);
	if (zero < 0)
		return 1;
	for (long i = 0; i < threads; i++)
		run_thread(quit);
	run_thread(read_zero);
	return 0;
}
