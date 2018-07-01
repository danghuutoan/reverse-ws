/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define DEST_PORT 8080
#define DEST_IP "192.168.0.125"


char* opening_handshake_str = 
"GET /chat HTTP/1.1\r\n"
"Host: server.example.com\r\n"
"Upgrade: websocket\r\n"
"Connection: Upgrade\r\n"
"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
"Origin: http://example.com\r\n"
"Sec-WebSocket-Protocol: chat, superchat\r\n"
"Sec-WebSocket-Version: 13\r\n"
"\r\n";
void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

int main(void) {
	int sockfd;
	int retval;
	char recv_buffer [4096];
	struct sockaddr_in dest_addr; // will hold the destination addr

	sockfd = socket(PF_INET, SOCK_STREAM, 0); // do some error checking!

	if(sockfd < 0){
		printf("create socket failed\n");
		exit(EXIT_FAILURE);
	}
	dest_addr.sin_family = AF_INET; // host byte order
	dest_addr.sin_port = htons(DEST_PORT); // short, network byte order
	dest_addr.sin_addr.s_addr = inet_addr(DEST_IP);
	memset(&(dest_addr.sin_zero), '\0', 8); // zero the rest of the struct

	// don't forget to error check the connect()!
	retval = connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr));

	if(retval < 0) {
		printf("socket connect failed\n");
		exit(EXIT_FAILURE);
	}

	retval = send(sockfd, opening_handshake_str, strlen(opening_handshake_str), 0);

	if(retval < 0) {
		printf("cannot send the msg \n");
		exit(EXIT_FAILURE);
	}

	retval = recv(sockfd, recv_buffer, 4096, 0);

	if(retval < 0) {
		printf("cannot receive msg from server \n");
		exit(EXIT_FAILURE);
	}

	printf("receive msg: %s\n", recv_buffer);

	memset(recv_buffer, 0, 4096);
	retval = recv(sockfd, recv_buffer, 4096, 0);

	if(retval < 0) {
		printf("cannot receive msg from server \n");
		exit(EXIT_FAILURE);
	}

	// printf("receive msg: %s\n", recv_buffer);
	// hexDump("recv_buffer", &recv_buffer, retval);
	// recv_buffer[2] = '8';
	retval = send(sockfd, "hello server", strlen("hello server"), 0);

	if(retval < 0) {
		printf("cannot send the msg \n");
		exit(EXIT_FAILURE);
	}

}
