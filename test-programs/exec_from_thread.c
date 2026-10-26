/*
 * Runs a command from a thread other than the main one, which the kernel
 * then makes the process's main thread, with the main thread's id.
 *
 * Build: cc -O2 -pthread -o exec_from_thread exec_from_thread.c
 * Usage: exec_from_thread command [arguments]
 */
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static void *run(void *command)
{
	char **argv = command;
	execvp(argv[0], argv);
	perror(argv[0]);
	_exit(2);
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;
	pthread_t thread;
	pthread_create(&thread, NULL, run, argv + 1);
	pause();
	return 0;
}
