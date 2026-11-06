/*
 * Test program whose thread makes known calls under three names: 3 calls
 * of getppid with the name it starts with, the program's, 5 once the main
 * thread names it by-main, which glibc does through its comm file, and 7
 * once it names itself by-itself, which glibc does with prctl.
 *
 * Build: cc -O2 -pthread -o renamed renamed.c
 * Usage: renamed
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <semaphore.h>
#include <sys/syscall.h>
#include <unistd.h>

static sem_t ready, named;

static void calls(int n)
{
	for (int i = 0; i < n; i++)
		syscall(SYS_getppid);
}

static void *run(void *arg)
{
	calls(3);
	sem_post(&ready);
	sem_wait(&named);
	calls(5);
	pthread_setname_np(pthread_self(), "by-itself");
	calls(7);
	return arg;
}

int main(void)
{
	sem_init(&ready, 0, 0);
	sem_init(&named, 0, 0);
	pthread_t thread;
	if (pthread_create(&thread, NULL, run, NULL) != 0)
		return 1;
	sem_wait(&ready);
	if (pthread_setname_np(thread, "by-main") != 0)
		return 1;
	sem_post(&named);
	pthread_join(thread, NULL);
	return 0;
}
