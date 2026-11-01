/*
 * The main thread sends UDP packets over loopback that another thread waits
 * for and receives.
 *
 * Build: cc -O2 -pthread -o udp udp.c
 * Usage: udp
 */
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static void *receive(void *socket)
{
	char byte;

	for (;;)
		recv(*(int *)socket, &byte, 1, 0);
}

int main(void)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t length = sizeof(address);
	int receiver = socket(AF_INET, SOCK_DGRAM, 0);
	int sender = socket(AF_INET, SOCK_DGRAM, 0);
	pthread_t thread;

	if (bind(receiver, (struct sockaddr *)&address, length) ||
	    getsockname(receiver, (struct sockaddr *)&address, &length) ||
	    connect(sender, (struct sockaddr *)&address, length))
		return 1;
	pthread_create(&thread, NULL, receive, &receiver);
	for (;;) {
		send(sender, "x", 1, 0);
		usleep(100);
	}
}
