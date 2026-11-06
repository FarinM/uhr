/*
 * Test program that makes known calls at two times: 100 calls of getppid
 * at its start, and 300 after it sleeps for 2.5 s.
 *
 * Build: cc -O2 -o phases phases.c
 * Usage: phases
 */
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static void calls(int n)
{
	for (int i = 0; i < n; i++)
		syscall(SYS_getppid);
}

int main(void)
{
	calls(100);
	struct timespec nap = { 2, 500000000 };
	nanosleep(&nap, NULL);
	calls(300);
	return 0;
}
