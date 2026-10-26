/*
 * Starts a process that exits at once, and right after it is reaped,
 * another with the same id, as checkpoint/restore tools can, which reads
 * /dev/zero a known number of times. A profiler that follows the processes
 * its target starts must not take the second for the first once it is gone.
 * Needs CAP_CHECKPOINT_RESTORE, as root has.
 *
 * Build: cc -O2 -o reuse reuse.c
 * Usage: reuse [reads]   (100000 by default)
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	long reads = argc > 1 ? atol(argv[1]) : 100000;

	pid_t first = fork();
	if (first == 0)
		_exit(0);
	waitpid(first, NULL, 0);

	struct clone_args args = {
		.exit_signal = SIGCHLD,
		.set_tid = (uint64_t)(uintptr_t)&first,
		.set_tid_size = 1,
	};
	long second = syscall(SYS_clone3, &args, sizeof(args));
	if (second < 0) {
		perror("clone3 with the first child's id");
		return 2;
	}
	if (second == 0) {
		char byte;
		int fd = open("/dev/zero", O_RDONLY);
		for (long i = 0; i < reads; i++)
			if (read(fd, &byte, 1) != 1)
				_exit(1);
		_exit(0);
	}
	int status;
	waitpid(second, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
