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

#define WS_FIN_MASK							(uint8_t)(0x80)
#define WS_FRAME_GET_FIN(buf) 				(uint8_t)((buf & WS_FIN_MASK) == WS_FIN_MASK)

#define WS_RSV1_MASK 						(uint8_t)(0x40)
#define WS_FRAME_GET_RSV1(buf) 				(uint8_t)((buf & WS_RSV1_MASK) == WS_RSV1_MASK)

#define WS_RSV2_MASK 						(uint8_t)(0x20)
#define WS_FRAME_GET_RSV2(buf) 				(uint8_t)((buf & WS_RSV2_MASK) == WS_RSV2_MASK)

#define WS_RSV3_MASK 						(uint8_t)(0x10)
#define WS_FRAME_GET_RSV3(buf) 				(uint8_t)((buf & WS_RSV3_MASK) == WS_RSV3_MASK)

#define WS_OPCODE_MASK 						(uint8_t)(0x0F)
#define WS_FRAME_GET_OPCODE(buf) 			(uint8_t)(buf & WS_OPCODE_MASK)

#define WS_FRAME_MASKED_MASK 				(uint8_t)(0x80)
#define WS_FRAME_GET_MASKED(buf)			(uint8_t)((buf & WS_FRAME_MASKED_MASK) == WS_FRAME_MASKED_MASK)

#define WS_FRAME_PAYLOAD_LEN_MASK			(uint8_t)(0X7F)
#define WS_FRAME_GET_PAYLOAD_LEN(buf)		(uint8_t)(buf & WS_FRAME_PAYLOAD_LEN_MASK)



typedef struct ws_frame_s {
	uint8_t fin;
	uint8_t rsv1;
	uint8_t rsv2;
	uint8_t rsv3;
	uint8_t opcode;
	uint8_t masked;
	uint64_t payload_len;
	uint8_t * data;
} ws_frame_t;

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

void ws_parse_frame(ws_frame_t* frame, char* buffer){
	frame->fin = WS_FRAME_GET_FIN(buffer[0]);
	frame->rsv1 = WS_FRAME_GET_RSV1(buffer[0]);
	frame->rsv2 = WS_FRAME_GET_RSV2(buffer[0]);
	frame->rsv3 = WS_FRAME_GET_RSV3(buffer[0]);
	frame->opcode = WS_FRAME_GET_OPCODE(buffer[0]);

	frame->masked = WS_FRAME_GET_MASKED(buffer[1]);
	frame->payload_len = WS_FRAME_GET_PAYLOAD_LEN(buffer[1]);
	if( frame->payload_len == 0x7e) {
		frame->payload_len = buffer[3] + (uint16_t)(buffer[2] << 8);
	}

	if( frame->payload_len == 0x7f ) {
		frame->payload_len = (uint64_t)buffer[9] + ((uint64_t)buffer[8] << 8) + ((uint64_t)buffer[7] << 16) + ((uint64_t)buffer[6] << 24) + ((uint64_t)buffer[5] << 32) + ((uint64_t)buffer[4] << 40) + ((uint64_t)buffer[5] << 48) + ((uint64_t)buffer[6] << 56);
	}
}

void ws_create_frame(ws_frame_t* frame, char*buffer)
{
	buffer[0] = 0;
	buffer[0] |= (frame->fin * WS_FIN_MASK);
	buffer[0] |= (frame->rsv1 * WS_RSV1_MASK);
	buffer[0] |= (frame->rsv2 * WS_RSV2_MASK);
	buffer[0] |= (frame->rsv3 * WS_RSV3_MASK);
	buffer[0] += frame->opcode;
	buffer[1] = 0;
	buffer[1] |= (frame->masked * WS_FRAME_MASKED_MASK);

	buffer[1] += frame->payload_len;

	
	// coppy data to buffer;
	memcpy( &buffer[2], frame->data, frame->payload_len);

}

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
	printf("debug line 173\n");	
	retval = recv(sockfd, recv_buffer, 4096, 0);

	if(retval < 0) {
		printf("cannot receive msg from server \n");
		exit(EXIT_FAILURE);
	}

	printf("receive msg: %s\n", recv_buffer);
	hexDump("recv_buffer", &recv_buffer, retval);
	// retval = send(sockfd, recv_buffer, retval, 0);

	// if(retval < 0) {
	// 	printf("cannot send the msg \n");
	// 	exit(EXIT_FAILURE);
	// }

	ws_frame_t frame;
	ws_parse_frame(&frame, recv_buffer);

	printf("fin %d\n", frame.fin);
	printf("rsv1 %d\n", frame.rsv1);
	printf("rsv2 %d\n", frame.rsv2);
	printf("rsv3 %d\n", frame.rsv3);
	printf("payload_len %lx\n", frame.payload_len);
	printf("masked %d\n", frame.masked);
	printf("opcode %d\n", frame.opcode);

	// uint8_t data [6] = {'1','2','3', '4', '5', '6'};
	uint8_t *data = "helllo every body hdjdsjdsjfdjfdjfdfdj";
	frame.fin = 1;
	frame.rsv1 = 0;
	frame.rsv2 = 0;
	frame.rsv3 = 0;
	frame.opcode = 0x01;
	frame.masked = 0;
	frame.payload_len = strlen(data);
	frame.data = data;
	char buffer[4096];
	ws_create_frame(&frame, buffer);
	hexDump("buffer", buffer, frame.payload_len + 2);	

	retval = send(sockfd, buffer, frame.payload_len + 2, 0);

	if(retval < 0) {
		printf("cannot send the msg \n");
		exit(EXIT_FAILURE);
	}

}
