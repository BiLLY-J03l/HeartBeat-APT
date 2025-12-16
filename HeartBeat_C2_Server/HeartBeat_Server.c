#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "c2_modules.h"

#define BUFFER_SIZE 2048
#define PORT_NO 1234

int main(void){
	
	
	//server hello msg
	//char server_message[500]="[+] YOU ARE CONNECTED TO THE SERVER\n";
	
	
	
	
	char server_ip[]="0.0.0.0";

	//create a socket
	//AF_INET ==> comms with ipv4
	//SOCK_STREAM ==> TCP
	//0 ==> IP protocol
	int server_socket=socket(AF_INET,SOCK_STREAM,0);
	if (server_socket == -1){
		perror("[x] socket() failed\n[x]exiting...\n");
		return -1;

	}

	//declare a pointer to sockaddr_in struct and allocate memory for it
	struct sockaddr_in *server_address = malloc(sizeof(struct sockaddr_in));

	server_address->sin_family=AF_INET;
	server_address->sin_port=htons(PORT_NO); //htons ==> convert port no. to network byte order
	
	//inet_pton ==> convert ip addr from string to binary, st0oring it in sin_addr
	if(inet_pton(AF_INET,server_ip,&(server_address->sin_addr)) <= 0){
		perror("[x] inet_pton() failed\n[x]exiting...\n");
		exit(EXIT_FAILURE);
	}
	
	//binding process
	if ( bind(server_socket,(struct sockaddr *)server_address,sizeof(*server_address)) != 0){
		perror("[x] bind() failed\n[x]exiting...\n");
		exit(EXIT_FAILURE);
	}

	//listening for connections
	if ( listen(server_socket, 10) != 0){
		perror("[x] listen() failed\n[x]exiting...\n");
		exit(EXIT_FAILURE);
	}
	printf("[+] listening on port %d...\n",PORT_NO);

	while (1){
	//accepting connections
		int client_socket=accept(server_socket, NULL, NULL);
		if (client_socket == -1){
			perror("[x] accept() failed\n[x]exiting...\n");
			exit(EXIT_FAILURE);
		}
		printf("[+] connection received...\n");
			
		//recv msg from agent
		// should recv basic sysinfo with password to complete auth
		char recv_buf[BUFFER_SIZE] = {0};
		ssize_t bytes_recieved = recv(client_socket,recv_buf,BUFFER_SIZE-1,0);
		if (bytes_recieved < 0){perror("[x] recv() failed\n");exit(EXIT_FAILURE);}

		//printf("[+] agent says: %s\n",recv_buf);	//debug
		


		if ( AuthClient(recv_buf) != 0 ){
			// maybe you can close that unauthenticated connection and keep listening
			close(client_socket);
		}
		else {break;}
	}

	printf("[+] Broken out of while loop and continuing hack\n");



	/*
	//sending msg
	printf("[+] sending hello message to client...\n");
	send(client_socket, server_message, sizeof(server_message),0);
	printf("[+] message sent...\n");
	
	//close connectiion
	printf("[+] closing connection...\n");
	close(server_socket);
	printf("[+] connection closed...\n");

	*/

	//free memory
	free(server_address);

	return 0;






}


