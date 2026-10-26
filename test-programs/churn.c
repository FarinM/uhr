/*
 * Starts and reaps processes one after another, more than a profiler
 * could keep track of at once, then starts one that reads /dev/zero a
 * known number of times. A profiler that follows the processes its target
 * starts has to let go of those that are gone to still follow the last.
 *
 * Build: cc -O2 -o churn churn.c
 * Usage: churn [processes] [reads]   (20000 and 1000 by default)
 */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	long processes = argc > 1 ? atol(argv[1]) : 20000;
	long reads = argc > 2 ? atol(argv[2]) : 1000;

	for (long i = 0; i < processes; i++) {
		pid_t pid = fork();
		if (pid == 0)
			_exit(0);
		waitpid(pid, NULL, 0);
	}
	pid_t reader = fork();
	if (reader == 0) {
		char byte;
		int fd = open("/dev/zero", O_RDONLY);
		for (long i = 0; i < reads; i++)
			if (read(fd, &byte, 1) != 1)
				_exit(1);
		_exit(0);
	}
	int status;
	waitpid(reader, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
