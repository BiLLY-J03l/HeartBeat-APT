#include <stdio.h>
#include <string.h>
#include <string.h>
#include "c2_modules.h"


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