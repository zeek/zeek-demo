#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>


int main(int argc, char *argv[]) {

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "Usage: %s <port>\n", argv[0]);
		exit(1);
	}

	int port = atoi(argv[1]);

	struct sockaddr_in listen_addr;
	memset(&listen_addr, 0, sizeof(struct sockaddr_in));
	listen_addr.sin_port = htons(port);
	listen_addr.sin_family = AF_INET;
	inet_pton(AF_INET, "0.0.0.0", &listen_addr.sin_addr);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket() failed");
		exit(1);
	}

	const int enable = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		close(fd);
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	if (bind(fd, (struct sockaddr*)&listen_addr, sizeof(struct sockaddr_in)) < 0) {
		perror("bind() failed");
		close(fd);
		exit(1);
	}

	// https://stackoverflow.com/questions/3086012/discard-incoming-udp-packet-without-reading
	// Setting udp_buf_size to 0 for dropping doesn't appear to work. Set
	// it to 16 MB.
	int udp_buf_size = 16 * 1024  * 1024;
	socklen_t optlen = sizeof(udp_buf_size);
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &udp_buf_size, optlen) < 0) {
		perror("setsockopt(SO_RCVBUF) failed - using default!");
		// If this failed, use whatever the default is.
		// close(fd);
		// exit(1);
	}

	// Make socket nonblocking
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		perror("setsockopt(SO_RCVBUF) failed");
		close(fd);
		exit(1);
	}


	// Busy poll for consuming all available packets queued on the socket
	// in non-blocking mode. Once none are left, sleep a bit for the
	// next batch. Mainly to avoid upsetting the scheduler too much.
	int r;
	char buf;
	socklen_t saddr_len;
	struct sockaddr_in saddr;
	unsigned long long packets = 0;
	while (1) {
		saddr_len = sizeof(struct sockaddr_in);
		while ((r = recvfrom(fd, &buf, 1, 0, (struct sockaddr*)&saddr, &saddr_len)) > 0) {
			++packets;
		}

		if ( r < 0 && errno != EAGAIN && errno != EWOULDBLOCK ) {
			perror("recvfrom() failed");
			break;
		}

		// Wait for packets.
		usleep(1000);
	}

	close(fd);
}
