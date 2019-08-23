#ifndef CHAT_SERVER_COMMON_H
#define CHAT_SERVER_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

#include <pthread.h>
#include <netinet/in.h>
#include <poll.h>

#include <sqlite3.h>
#include <sodium.h>
#include <uthash.h>

#define MAX_ROOMS 11
#define LOBBY_ROOM_ID 0

#define USERNAME_SIZE 16
#define PASSWORD_SIZE_MIN 4
#define PASSWORD_SIZE_MAX 16

#define MESSAGE_SIZE 256
#define WHO_MESSAGE_SIZE 32 //NOTE: Array will be reallocated if needed

#define MESSAGE_END 0x03 //End-of-Text control character
#define MESSAGE_START 0x02 //Start-of-Text control character
#define MESSAGE_START_STR "\x02" //Start-of-Text control character as a string
#define SERVER_PREFIX "Server: " //Message prefix for server messages

#define PWHASH_OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE //Use crypto_pwhash_OPSLIMIT_MODERATE for higher security
#define PWHASH_MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE //Use crypto_pwhash_MEMLIMIT_MODERATE for higher security

typedef struct {
    char id[USERNAME_SIZE];  /* key */
    bool is_admin;
    int room_id;
    size_t index;
    int socket_fd;
    char ip[INET_ADDRSTRLEN];
    unsigned short port;
    char *message;
    size_t message_size;
    UT_hash_handle hh;         /* makes this structure hashable */
} table_entry_t;

extern int socket_count;
extern struct pollfd socket_fds[];
extern table_entry_t *active_users[]; 

extern short spam_message_count[]; //Spam message counters for each client
extern short spam_timeout[]; //Spam timeout for each client
extern pthread_mutex_t spam_lock;

extern sqlite3 *user_db;

#endif