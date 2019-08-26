#ifndef CHAT_SERVER_VALUES_H
#define CHAT_SERVER_VALUES_H

#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>

#include "server_shared.h"
#include "server_commands.h"
#include "server_utils.h"

#define DEFAULT_PORT_NUMBER 9852 //Default port number to try before automatically finding an unused port
#define LISTEN_BACKLOG 10
#define MAX_SOCKETS 256 //Max FD limit on linux is set to 1024 by default but can be changed

#define SPAM_MESSAGE_LIMIT 10 //Max messages within spam interval window
#define SPAM_INTERVAL_WINDOW 10 //Interval window (in seconds) for max message limit
#define SPAM_TIMEOUT_LENGTH 20 //Timeout period (in seconds) for detected spammer to wait

void open_database();
void create_admin();
void start_server();
void *spam_timer();
void monitor_connections(int);
void accept_clients(int, char *, char **);
void process_clients(char *, char **);
int check_for_spamming(table_entry_t *, char *);
void private_message(table_entry_t *, char *, size_t, char *);
void public_message(table_entry_t *, char *, size_t);
void remove_client(table_entry_t *, char *, char **);
static void terminate_server(int sig_num);
void shutdown_server(char **);

#endif