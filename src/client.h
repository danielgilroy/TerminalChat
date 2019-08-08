#ifndef CHAT_CLIENT_H
#define CHAT_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <pthread.h>
#include <signal.h>
#include <ncurses.h>

#include "client_tcp.h"

#define DEFAULT_PORT_NUMBER 9852
#define DEFAULT_IP_ADDRESS "127.0.0.1"
#define MESSAGE_LENGTH 256
#define MESSAGE_START 0x02

void initialize_chat();
void initialize_connection(char *, int);
void terminate_chat();
void terminate_chat_now();
void *incoming_messages();
void outgoing_messages();
void print_to_chat(char *, int);
void print_time();
static void handler(int);
static void sig_handler(int);

#endif