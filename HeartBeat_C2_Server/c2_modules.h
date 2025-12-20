#pragma once

int AuthClient(char *recv_buf);
void decrypt(unsigned char* recv_buf, size_t recv_buf_size);
void encrypt(unsigned char* recv_buf, size_t recv_buf_size);
void HandleLspid(char *cmd, int client_socket);
void HandleShell(char *cmd,int client_socket);
void HandleStopProcess(char *cmd, int client_socket);