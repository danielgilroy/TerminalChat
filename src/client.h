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

#define INPUT_INDICATOR "Send> "
#define INPUT_START 6 //Adjust this based on INPUT_INDICATOR

void initialize_chat();
void initialize_connection(char *, int);
void process_messages();
void *incoming_messages();
void outgoing_messages();
bool get_user_message(char *, size_t *);
void print_to_chat(char *, int);
void print_time();
void shutdown_chat();
static void shutdown_handler(int);

#endif