/*
 * Test program that embeds CPython from its shared library and runs a
 * Python function, spin(), for about 300 ms on a 3.5 GHz core.
 *
 * Build: cc -O2 -I<include> -o embed embed.c -L<libdir> -lpython3.X \
 *        -Wl,-rpath,<libdir>
 * Usage: embed
 */
#include <Python.h>

int main(void)
{
	Py_Initialize();
	int failed = PyRun_SimpleString("def spin():\n"
					"    total = 0\n"
					"    for i in range(15000000):\n"
					"        total += i\n"
					"    return total\n"
					"\n"
					"spin()\n");
	Py_Finalize();
	return failed ? 1 : 0;
}
