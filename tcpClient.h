#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MESSAGE_LENGTH 256

int join_server(char *, int, char *);
int receive_message(char *, int);
int send_message(char *, int);
int close_socket(int);
void check_status(int);

#endif