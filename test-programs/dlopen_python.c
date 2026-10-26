/*
 * Test program that spins in C for about 350 ms on a 3.5 GHz core, then
 * loads CPython's shared library with dlopen, as a program loads a plugin,
 * and runs a Python function, spin(), for about 300 ms.
 *
 * Build: cc -O2 -fno-omit-frame-pointer -o dlopen_python dlopen_python.c -ldl
 * Usage: dlopen_python <libpython>
 */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

#if defined(__clang__)
#define KEEP __attribute__((noinline))
#else
#define KEEP __attribute__((noipa))
#endif

/* A chain of dependent shifts and xors, which can't be optimized away. */
KEEP uint64_t native_spin(uint64_t x, uint64_t n)
{
	for (uint64_t i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
	return x;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: dlopen_python <libpython>\n");
		return 2;
	}
	uint64_t x = native_spin(88172645463325252ULL, 310000000);
	/* Global, as the extension modules Python loads take its symbols. */
	void *python = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
	if (!python) {
		fprintf(stderr, "%s\n", dlerror());
		return 1;
	}
	void (*initialize)(void) = (void (*)(void))dlsym(python, "Py_Initialize");
	int (*run)(const char *) = (int (*)(const char *))dlsym(python, "PyRun_SimpleString");
	void (*finalize)(void) = (void (*)(void))dlsym(python, "Py_Finalize");
	if (!initialize || !run || !finalize) {
		fprintf(stderr, "%s has no Py_Initialize, PyRun_SimpleString or Py_Finalize\n", argv[1]);
		return 1;
	}
	initialize();
	int failed = run("def spin():\n"
			 "    total = 0\n"
			 "    for i in range(15000000):\n"
			 "        total += i\n"
			 "    return total\n"
			 "\n"
			 "spin()\n");
	finalize();
	return failed || x == 0 ? 1 : 0;
}
