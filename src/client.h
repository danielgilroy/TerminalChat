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

void initialize_chat();
void initialize_connection(char *, int);
void *incoming_messages();
void outgoing_messages();
void print_to_chat(char *, int);
void print_time();
void shutdown_chat();
static void shutdown_handler(int);

#endif