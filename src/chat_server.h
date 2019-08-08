#ifndef CHAT_SERVER_VALUES_H
#define CHAT_SERVER_VALUES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <poll.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <sqlite3.h>
#include <sodium.h>
#include <uthash.h>

#define DEFAULT_PORT_NUMBER 9852 //Default port number to try before automatically finding an unused port
#define LISTEN_BACKLOG 10
#define POLL_TIMEOUT 400 //Poll timeout in milliseconds: Reduce this if joining chat takes too long
#define MAX_SOCKETS 256 //Max FD limit on linux is set to 1024 by default but can be changed

#define MAX_ROOMS 11
#define LOBBY_ROOM_ID 0
#define USERNAME_LENGTH 16
#define PASSWORD_LENGTH_MIN 4
#define PASSWORD_LENGTH_MAX 16

#define QUERY_LENGTH 256
#define MESSAGE_LENGTH 256
#define MESSAGE_START 0x02 //Start of Text control character
#define WHO_MESSAGE_LENGTH 32 //NOTE: Array will be reallocated if needed

#define SPAM_MESSAGE_LIMIT 10 //Max messages within spam interval window
#define SPAM_INTERVAL_WINDOW 10 //Interval window (in seconds) for max message limit
#define SPAM_TIMEOUT_LENGTH 20 //Timeout period (in seconds) for detected spammer to wait

#define PWHASH_OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE //Use crypto_pwhash_OPSLIMIT_MODERATE for higher security
#define PWHASH_MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE //Use crypto_pwhash_MEMLIMIT_MODERATE for higher security

typedef struct {
    char id[USERNAME_LENGTH];  /* key */
    size_t index;
    bool is_admin;
    int socket_fd;
    char ip[INET_ADDRSTRLEN];
    unsigned short port;
    UT_hash_handle hh;         /* makes this structure hashable */
} table_entry_t;

void open_database();
void create_admin();
void start_server();
void *spam_timer();
void monitor_connections(int);
void accept_clients(int, char *, char **);
void process_clients(char *, char *, char **);
int check_for_spamming(table_entry_t *, char *);
void private_message(table_entry_t *, int, char *, char *);
void public_message(int, int, char *, char *);
void remove_client(table_entry_t *, int, char *, char **);
void shutdown_server(char *, char **);

extern int socket_count;
extern struct pollfd socket_fds[];
extern table_entry_t *active_users[]; 

extern short spam_message_count[]; //Spam message counters for each client
extern short spam_timeout[]; //Spam timeout for each client
extern pthread_mutex_t spam_lock;

extern sqlite3 *user_db;

#endif