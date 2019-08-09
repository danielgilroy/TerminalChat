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

#define DEFAULT_PORT_NUMBER 9852
#define DEFAULT_IP_ADDRESS "127.0.0.1"
#define MESSAGE_LENGTH 256
#define MESSAGE_START 0x02

int join_server(char *, unsigned int, char *);
int receive_message(char *, int);
int send_message(char *, int);
int close_socket(int);
void check_status(int);

#endif