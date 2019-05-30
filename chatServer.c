#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <poll.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <sqlite3.h>
#include <sodium.h>

#include "uthash.h"

#define PORT_NUMBER 9002
#define LISTEN_BACKLOG 10
#define POLL_TIMEOUT 400 //Poll timeout in milliseconds: Reduce this if joining chat takes too long
#define MAX_SOCKETS 256 //Max FD limit on linux is set to 1024 by default
#define MAX_ROOMS 11
#define LOBBY_ROOM_ID 0
#define USERNAME_LENGTH 16
#define PASSWORD_LENGTH_MAX 16
#define PASSWORD_LENGTH_MIN 4
#define SALT_LENGTH 3
#define WHO_LENGTH 64
#define QUERY_LENGTH 256
#define MESSAGE_LENGTH 256
#define MESSAGE_START 0x02 //Start of Text control character
#define SPAM_MESSAGE_LIMIT 10 //Max messages within spam interval window
#define SPAM_INTERVAL_WINDOW 10 //Interval window (in seconds) for max message limit
#define SPAM_TIMEOUT_LENGTH 20 //Timeout period (in seconds) for detected spammer to wait
#define PWHASH_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE //use crypto_pwhash_OPSLIMIT_INTERACTIVE if too slow
#define PWHASH_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE //use crypto_pwhash_MEMLIMIT_INTERACTIVE if too slow

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
void start_server();
void *spam_filter();
void process_clients(int);

int send_message(int, char *, int);
int send_message_to_all(int, char *, int);
char *add_username_to_message(char *, char *, char *);
void print_time();
int check_status(int, char *);
void get_username_and_passwords(int, char *, char **, char **, char **);
int is_password_valid(char *, char *);
int are_passwords_valid(char *, char *, char *);
int is_username_valid(char *, char *);
int is_username_restricted(char *, char *);
void rebuild_who_message(char **, int);
void remove_user(int, table_entry_t *);
void add_user(int, char *, size_t, bool, int, char *, unsigned short);
table_entry_t *get_user(int, char *);
void change_username(int, table_entry_t *, char *);
void delete_user(int, table_entry_t *);
int id_compare(table_entry_t *, table_entry_t *);
static int callback(void *, int, char **, char **);

struct pollfd socket_fds[MAX_SOCKETS];
int socket_count = 0;
bool shutdown_server = false;
pthread_mutex_t shutdown_lock;

table_entry_t *active_users[MAX_ROOMS] = {NULL, }; 

short spam_message_count[MAX_SOCKETS]; //Spam message counters for each client
short spam_timeout[MAX_SOCKETS]; //Spam timeout for each client
pthread_mutex_t spam_lock;

sqlite3 *user_db;

int main(){

    pthread_mutex_init(&shutdown_lock, NULL);
    pthread_mutex_init(&spam_lock, NULL);
    
    printf("**Opening Database**\n");
    open_database();
    printf("**Starting Server**\n");
    start_server();

    printf("**Shutting Down Server**\n");

    pthread_mutex_destroy(&shutdown_lock);
    pthread_mutex_destroy(&spam_lock);

    return 0;
}

void open_database(){

    int status;
    const char *query;
    char user_input_query[QUERY_LENGTH];
    char *has_result = NULL;
    char *error_message = NULL;
    
    //Open database of registered users
    status = sqlite3_open("users.db", &user_db);
    if(status != SQLITE_OK){
        fprintf(stderr, "Error opening database: %s\n", sqlite3_errmsg(user_db));
        sqlite3_close(user_db);
    }

    //Create "users" table if it does not exist    
    query = "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY NOT NULL, password TEXT NOT NULL, type TEXT NOT NULL);";
    status = sqlite3_exec(user_db, query, callback, NULL, &error_message);
    if(status != SQLITE_OK){
        //Print SQL error to the server terminal
        fprintf(stderr, "SQL query error: %s\n", error_message);
        sqlite3_free(error_message);
    }

    //Check if initial admin account has already been created
    query = "SELECT 1 FROM users WHERE type = 'admin'";
    status = sqlite3_exec(user_db, query, callback, &has_result, &error_message);
    if(status != SQLITE_OK){
        //Print SQL error to the server terminal
        fprintf(stderr, "SQL query error: %s\n", error_message);
        sqlite3_free(error_message);
    }

    //Create initial admin account if it doesn't exist
    if(!has_result){

        char admin_password[MESSAGE_LENGTH];
        char admin_password2[MESSAGE_LENGTH];
        char hashed_password[crypto_pwhash_STRBYTES];
        char password_error[MESSAGE_LENGTH];
        char *matching_error = "";
        char *newline = NULL;

        printf("**Creating Admin Account**\n");

        //Get admin password from server administrator
        do{

            //Reset password_error for new itteration
            password_error[0] = '\0';

            //Print error message from previous itteration
            if(*matching_error){
                printf("%s\n\n", matching_error);
            }

            do{
                if(*password_error){ //Print error message if not blank
                    printf("%s\n\n", password_error + 8); //Add 8 to skip over "Server: " prefix
                }
                printf("Enter password for account \"Admin\": ");
                fgets(admin_password, MESSAGE_LENGTH, stdin);
                if((newline = strchr(admin_password, '\n')) != NULL){
                    *newline = '\0'; //Remove newline from user input
                }
            }while(!is_password_valid(admin_password, password_error));

            printf("Retype the same password: ");
            fgets(admin_password2, MESSAGE_LENGTH, stdin);
            if((newline = strchr(admin_password2, '\n')) != NULL){
                *newline = '\0'; //Remove newline from user input
            }

            //Set matching_error message for next loop itteration
            matching_error = "The entered passwords do not match";

        }while(strcmp(admin_password, admin_password2) != 0);

        //Hash password with libsodium
        if (crypto_pwhash_str(hashed_password, admin_password, strlen(admin_password), 
            PWHASH_OPSLIMIT, PWHASH_MEMLIMIT) != 0) {
            /* out of memory */
            fprintf(stderr, "Ran out of memory during hash function\n");
            exit(EXIT_FAILURE);
        }
    
        //Clear the plain-text passwords from memory
        memset(admin_password, 0, PASSWORD_LENGTH_MAX);
        memset(admin_password2, 0, PASSWORD_LENGTH_MAX);
        
        //Register admin account into database with specified password
        snprintf(user_input_query, QUERY_LENGTH, "INSERT INTO users(id, password, type) VALUES('Admin', '%s', 'admin');", hashed_password);
        status = sqlite3_exec(user_db, user_input_query, callback, NULL, &error_message);
        if(status != SQLITE_OK){
            fprintf(stderr, "SQL query error: %s\n", error_message);
            sqlite3_free(error_message);
        }else{
            printf("**Admin Account Created**\n");
        }

    }else{
        free(has_result);
    }

}

void start_server(){

    int status;
    int flags;
    
    //Define the server's IP address and port
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT_NUMBER);
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    memset(server_address.sin_zero, 0, sizeof(server_address.sin_zero));

    //Create the server socket to use for a connection
    int server_socket;
    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    check_status(server_socket, "Error creating server socket");

    //Set server socket to nonblocking
    flags = fcntl(server_socket, F_GETFL, NULL);
    check_status(flags, "Error getting flags for server socket");
    status = fcntl(server_socket, F_SETFL, flags | O_NONBLOCK);
    check_status(status, "Error setting server socket to nonblocking");

    //Bind the socket to our specified IP address and port
    status = bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));
    check_status(status, "Error binding server socket");

    //Set the socket up to listen for connections
    status = listen(server_socket, LISTEN_BACKLOG);
    check_status(status, "Error listening on server socket");

    //Initialize struct pollfd array to zeros
    memset(socket_fds, 0, sizeof(socket_fds));

    //Set server file descriptor and event type
    socket_fds[0].fd = server_socket;
    socket_fds[0].events = POLLIN;
    socket_count++;

    //Set ignore state for client file descriptors and event type
    for(size_t i = 1; i < MAX_SOCKETS; i++){
        socket_fds[i].fd = -1;
        socket_fds[i].events = POLLIN;
    }

    //Create thread for spam filter
    pthread_t spam_tid;
    pthread_create(&spam_tid, NULL, spam_filter, NULL);

    //Call method for processing clients
    process_clients(server_socket);

    //Wait for thread to finish
    pthread_join(spam_tid, NULL);

    //Close the server socket
    status = close(server_socket);
    check_status(status, "Error closing server socket");

    //Close database of registered users
    status = sqlite3_close(user_db);
    if(status != SQLITE_OK){
        fprintf(stderr, "Error closing database: %s\n", sqlite3_errmsg(user_db));
    }

}

void *spam_filter(){

    int current_interval = 0; //Current interval within spam interval window

    while(1){

        //Each interval is one second long
        sleep(1);
        current_interval++;

        //Reset spam message counters to be used in new spam interval window
        if(current_interval % SPAM_INTERVAL_WINDOW == 0){
            pthread_mutex_lock(&spam_lock);
            memset(spam_message_count, 0, sizeof(spam_message_count));
            pthread_mutex_unlock(&spam_lock);
            current_interval = 0;
        }

        //Reduce every client's timeout period by one second until it's zero
        pthread_mutex_lock(&spam_lock);
        for(size_t i = 1; i < MAX_SOCKETS; i++){
            if(spam_timeout[i] > 0){
                spam_timeout[i]--;
            }
        }
        pthread_mutex_unlock(&spam_lock);

        pthread_mutex_lock(&shutdown_lock);
        if(shutdown_server){
            pthread_mutex_unlock(&shutdown_lock);
            break;
        }
        pthread_mutex_unlock(&shutdown_lock);
        
    }

    return NULL;
}

void process_clients(int server_socket){

    int status, flags;
    int recv_status;
    int client_socket;
    size_t index = 1; //Start at 1 to skip server socket
    bool message_recv[MAX_SOCKETS] = {false};
    char username[USERNAME_LENGTH];
    char client_message[MESSAGE_LENGTH + 1];
    char server_message_prefixed[MESSAGE_LENGTH];
    char *server_message = server_message_prefixed + 1;
    char *who_message[MAX_ROOMS] = {NULL};
    char query[QUERY_LENGTH];
    int8_t command_length = 0;

    //Add control character to the start of message so we know when it's a
    //new message since the message may be split up over multiple packets
    server_message_prefixed[0] = MESSAGE_START;

    //Extra fail safe to ensure NULL terminated client message
    client_message[MESSAGE_LENGTH] = '\0';

    //Allocate initial space for who_message strings and set them to rebuild state
    for(int room_id = 0; room_id < MAX_ROOMS; room_id++){
        who_message[room_id] = malloc(sizeof(char) * WHO_LENGTH);
        if(who_message[room_id] == NULL){
            fprintf(stderr, "Error allocating memory for who_message room #%d\n", room_id);
            exit(0);
        }
        who_message[room_id][0] = '\0';
    }

    printf("**Awaiting Clients**\n");
        
    while(1){
        
        //Monitor FDs for any activated events
        status = poll(socket_fds, MAX_SOCKETS, POLL_TIMEOUT);
        
        //Timeout occurred: Clients don't have any events or errors
        if(status == 0){
            //printf("Client FDs: %d %d %d %d\n", socket_fds[0].fd, socket_fds[1].fd, socket_fds[2].fd, socket_fds[3].fd);
            continue;
        }
        //A poll error has occurred
        if(status == -1){
            perror("Error");
            continue;
        }
    
        /* ------------------------------------------ */
        /* An event has occurred: Check server socket */
        /* ------------------------------------------ */
        if(socket_fds[0].revents & POLLIN){

            struct sockaddr_in client_addr;
            socklen_t client_addr_size = sizeof(client_addr);
            char ip_str[INET_ADDRSTRLEN];
            unsigned short port;

            while(1){
            
                //Check for any pending connections
                client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &client_addr_size);

                //Accept all pending connections until the queue is empty
                if(client_socket == -1){
                    break;
                }
    
                //Check if server is full
                if(socket_count >= MAX_SOCKETS){
                    printf("**Server has reached the maximum of %d clients**\n", MAX_SOCKETS - 1);
                    sprintf(server_message, "Server: The server has reached the maximum of %d clients", MAX_SOCKETS - 1);
                    send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                    status = close(client_socket);
                    check_status(status, "Error closing client socket");
                    continue;
                }

                //Increment socket count and set lobby who_message for rebuild
                socket_count++;
                who_message[LOBBY_ROOM_ID][0] = '\0';
                
                //Set client socket to nonblocking
                flags = fcntl(client_socket, F_GETFL);
                check_status(flags, "Error getting flags for client socket");
                status = fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
                check_status(status, "Error setting client socket to nonblocking");
                
                //Get the ip address and port number of the connecting user
                inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, sizeof(ip_str));
                port = ntohs(client_addr.sin_port);

                //Find an available spot in the client FD array
                while(socket_fds[index].fd > 0){
                    index = (index + 1) % MAX_SOCKETS;
                }

                //Assign the socket to the client FD
                socket_fds[index].fd = client_socket;

                //Create client's default username
                sprintf(username, "Client%zu", index);

                //Add client to the lobby room in active_users hash table
                add_user(LOBBY_ROOM_ID, username, index, false, client_socket, ip_str, port);

                //Send server welcome messages to client
                sprintf(server_message, "Server: Welcome to the server - Default username is \"%s\"", username);
                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                sprintf(server_message, "Server: Use the /nick command to change your username");
                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                sprintf(server_message, "Server: Use the /join command to join a chat room");
                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1); 
                
                //Print client joining message to the server's terminal
                printf("**Client%lu on socket %d (%s:%hu) joined the server**\n", index, client_socket, ip_str, port);

            }
        }

        /* ----------------------------------------------------------------- */
        /* An event has occurred: Check all active clients in all chat rooms */
        /* ----------------------------------------------------------------- */
        memset(message_recv, false, sizeof(message_recv));
        //printf("\n");
        for(int room_id = 0; room_id < MAX_ROOMS; room_id++){

            //Itterate through all users in the chat room
            table_entry_t *user, *tmp;
            HASH_ITER(hh, active_users[room_id], user, tmp){ //Deletion-safe itteration

                //Get index and username from user
                size_t i = user->index;
                strncpy(username, user->id, USERNAME_LENGTH);

                //Check if user has already been processed
                if(message_recv[i]){
                    continue;
                }

                /* DEBUG STATEMENT */
                //printf("Process %s in room %d\n", username, room_id);
                /* --------------- */

                if(socket_fds[i].revents & POLLIN){

                    client_socket = user->socket_fd;

                    //Receive messages from client sockets with active events
                    recv_status = recv(client_socket, client_message, MESSAGE_LENGTH, 0);
                    if(recv_status == -1 && (errno != EWOULDBLOCK && errno != EAGAIN)){
                        perror("Error receiving message from client socket");
                        continue;
                    }
                    if(recv_status > strlen(client_message) + 1){
                        fprintf(stderr, "Need to handle multiple messages in a single packet\n");
                    }

                    //Mark user as processed
                    message_recv[i] = true;

                    if(recv_status == 0){

                        /* -------------------------- */
                        /* Client has left the server */
                        /* -------------------------- */

                        //Print message to server terminal
                        printf("**%s in room #%d left the server**\n", username, room_id);
                    
                        //Print message to chat room
                        sprintf(server_message, "Server: %s left the server", username);
                        send_message_to_all(room_id, server_message_prefixed, strlen(server_message_prefixed) + 1);

                        //Remove client entry from server
                        remove_user(room_id, user);

                        //Set who_message for rebuild
                        who_message[room_id][0] = '\0';

                        continue;
                    }


                    /* ------------------------------------- */
                    /* Prepare client's message for handling */
                    /* ------------------------------------- */

                    //Replace ending \n with \0 or ending \r\n with \0\0
                    if(client_message[recv_status-1] == '\n'){
                        client_message[recv_status-1] = '\0';
                        if(recv_status > 1 && client_message[recv_status-2] == '\r'){
                            client_message[recv_status-2] = '\0';
                            recv_status--;
                        }
                    }     

                    //Null terminate message if it didn't have \n, \r\n, or \0 already
                    if(client_message[recv_status - 1] != '\0'){
                        client_message[recv_status] = '\0';
                    }
                    

                    /* ------------------------------- */
                    /* Process client's server command */
                    /* ------------------------------- */
                    if(client_message[0] == '/'){
        
                        //List who's in every chat room
                        if(strcmp(client_message, "/who") == 0){
                        
                            for(int i = 1; i < MAX_ROOMS; i++){
                                //Rebuild who_message strings if necessary
                                rebuild_who_message(who_message, i);

                                //Send message containing current users in room #i
                                send_message(client_socket, who_message[i], strlen(who_message[i]) + 1);
                            }

                            continue;
                        }

                        //List who's in the specified chat room
                        if(strncmp(client_message, "/who ", 5) == 0){
                            
                            //Check if argument after /who is valid
                            if(!isdigit(client_message[5])){
                                sprintf(server_message, "Server: Enter a valid room number (1 to %d) after /who", MAX_ROOMS - 1);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;    
                            }
                            
                            //Get room number from user
                            char *targeted_room = client_message + 5;
                            int targeted_room_id = atoi(targeted_room);
                            
                            //Check if chat room is valid
                            if(targeted_room_id >= MAX_ROOMS || targeted_room_id < 0){
                                sprintf(server_message, "Server: Specified room doesn't exist (valid rooms are 1 to %d)", MAX_ROOMS - 1);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Set target_room_id to current room if zero
                            if(targeted_room_id == 0){
                                targeted_room_id = room_id;
                            }

                            //Rebuild who_message strings if necessary
                            rebuild_who_message(who_message, targeted_room_id);

                            //Send message containing current users in the specified room
                            send_message(client_socket, who_message[targeted_room_id], strlen(who_message[targeted_room_id]) + 1);
                            continue; 
                        }

                        //Join the specified chat room
                        if(strncmp(client_message, "/join ", 6) == 0){

                            //Check if argument after /join is valid
                            if(!isdigit(client_message[6])){
                                sprintf(server_message, "Server: Enter a valid room number (0 to %d) after /join", MAX_ROOMS - 1);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;    
                            }
                            
                            //Get new room number from user
                            char *new_room = client_message + 6;
                            int new_room_id = atoi(new_room);

                            //Check if chat room is valid
                            if(new_room_id >= MAX_ROOMS || new_room_id < 0){
                                sprintf(server_message, "Server: Specified room doesn't exist (valid rooms are 0 to %d)", MAX_ROOMS - 1);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Check if already in the room
                            if(room_id == new_room_id){
                                sprintf(server_message, "Server: You are already in room #%d", room_id);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;                                
                            }

                            //Print client joining message to the server's terminal
                            printf("**%s changed from room #%d to room #%d**\n", username, room_id, new_room_id);

                            //Send message letting clients in new room know someone joined the room
                            sprintf(server_message, "Server: User \"%s\" joined the chat room", username);
                            send_message_to_all(new_room_id, server_message_prefixed, strlen(server_message_prefixed) + 1);
                            
                            //Move user to the new chat room
                            add_user(new_room_id, username, user->index, user->is_admin, user->socket_fd, user->ip, user->port);
                            delete_user(room_id, user);

                            //Send message letting clients in old chat room know someone changed rooms
                                sprintf(server_message, "Server: User \"%s\" switched to chat room #%d", username, new_room_id);
                                send_message_to_all(room_id, server_message_prefixed, strlen(server_message_prefixed) + 1);
                            
                            //Send message to client who just joined the room
                            sprintf(server_message, "Server: You have joined chat room #%d", new_room_id);
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);

                            //Set both room's who_message for rebuild
                            who_message[room_id][0] = '\0';
                            who_message[new_room_id][0] = '\0';

                            continue;
                        }

                        //Echo back the client's username
                        if(strcmp(client_message, "/nick") == 0){
                            sprintf(server_message, "Server: Your username is \"%s\"", username);
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                            continue;
                        }

                        //Change the client's username
                        if(strncmp(client_message, "/nick ", command_length = 6) == 0){

                            char *new_name = NULL;
                            char *password = NULL;
                            char *db_password = NULL;
                            char hashed_password[crypto_pwhash_STRBYTES];
                            char *user_type = NULL;
                            char *error_message = NULL;

                            //Get username and one password from client's message
                            get_username_and_passwords(command_length, client_message, &new_name, &password, NULL);
                                                  
                            //Check if the username is valid or restricted
                            if(!is_username_valid(new_name, server_message) || !is_username_restricted(new_name, server_message)){
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }       

                            //Check if client already has the username
                            if(strcmp(username, new_name) == 0){
                                sprintf(server_message, "Server: Your username is already \"%s\"", new_name);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Check if username is registered in database     
                            snprintf(query, QUERY_LENGTH, "SELECT password FROM users WHERE id = '%s';", new_name);
                            status = sqlite3_exec(user_db, query, callback, &db_password, &error_message);
                            if(status != SQLITE_OK){
                                //Print SQL error to the server terminal
                                fprintf(stderr, "SQL query error: %s\n", error_message);
                                sqlite3_free(error_message);
                            }

                            if(db_password){ //Username requires a password
                                /* DEBUG PRINT */
                                printf("The SQL query returned: %s\n", db_password);
                                /* ----------- */

                                //Return error message if client did not specify a password
                                if(password == NULL){
                                    sprintf(server_message, "Server: The username \"%s\" requires a password", new_name);
                                    send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                    free(db_password);
                                    continue;
                                }

                                //Check if password is valid
                                if(!is_password_valid(password, server_message)){
                                    send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                    //Clear the plain-text password from memory
                                    memset(client_message, 0, MESSAGE_LENGTH);
                                    continue;     
                                }

                                //Compare database password with client password using libsodium
                                if(crypto_pwhash_str_verify(db_password, password, strlen(password)) != 0){
                                    sprintf(server_message, "Server: The specified password was incorrect");
                                    send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                    free(db_password);
                                    //Clear the plain-text password from memory
                                    memset(client_message, 0, MESSAGE_LENGTH);
                                    continue;
                                }

                                //Check if hashed password needs to be rehashed
                                if(crypto_pwhash_str_needs_rehash(db_password, PWHASH_OPSLIMIT, PWHASH_MEMLIMIT) != 0){
 
                                    //Hash password with libsodium
                                    if(crypto_pwhash_str(hashed_password, password, strlen(password), PWHASH_OPSLIMIT, PWHASH_MEMLIMIT) != 0) {
                                        fprintf(stderr, "Ran out of memory during hash function\n");
                                        exit(EXIT_FAILURE);
                                    }
                                    
                                    //Change password for the registered user
                                    snprintf(query, QUERY_LENGTH, "UPDATE users SET password = '%s' WHERE id = '%s';", hashed_password, new_name);
                                    status = sqlite3_exec(user_db, query, callback, NULL, &error_message);
                                    if(status != SQLITE_OK){
                                        fprintf(stderr, "SQL query error: %s\n", error_message);
                                        sqlite3_free(error_message);
                                        //Clear the plain-text password from memory
                                        memset(client_message, 0, MESSAGE_LENGTH);
                                        continue;
                                    }
                                }

                                //Get user type from the database
                                snprintf(query, QUERY_LENGTH, "SELECT type FROM users WHERE id = '%s';", new_name);
                                status = sqlite3_exec(user_db, query, callback, &user_type, &error_message);
                                if(status != SQLITE_OK){
                                    //Print SQL error to the server terminal
                                    fprintf(stderr, "SQL query error: %s\n", error_message);
                                    sqlite3_free(error_message);
                                }

                                free(db_password);

                            }else{ //Username is not registered
                                printf("The SQL query had no results\n");
                            }
                            
                            //Check if username is already in use on the server
                            bool name_in_use = false;
                            for(int i = 0; i < MAX_ROOMS; i++){
                                if(get_user(i, new_name) != NULL){
                                    name_in_use = true;
                                    break;
                                }
                            }
                            if(name_in_use){
                                sprintf(server_message, "Server: The username \"%s\" is currently in use", new_name);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                //Clear the plain-text password from memory
                                memset(client_message, 0, MESSAGE_LENGTH);
                                continue;
                            }     

                            //Check if database returned an admin user type
                            if(user_type && strcmp(user_type, "admin") == 0){
                                user->is_admin = true;
                            }else{
                                user->is_admin = false; 
                            }
                            free(user_type);

                            //Change username in active_users hash table
                            change_username(room_id, user, new_name);

                            //Set who_message for rebuild
                            who_message[room_id][0] = '\0';
                            
                            //Print name change message to server's terminal
                            printf("**%s on socket %d changed username to %s**\n", username, client_socket, new_name);
                            
                            //Send name change message to all clients if not in lobby
                            if(room_id != LOBBY_ROOM_ID){
                                sprintf(server_message, "Server: %s changed their name to %s", username, new_name);
                                send_message_to_all(room_id, server_message_prefixed, strlen(server_message_prefixed) + 1);
                            }else{
                                sprintf(server_message, "Server: Your username has been changed to \"%s\"", new_name);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);  
                            }

                            //Clear the plain-text password from memory
                            memset(client_message, 0, MESSAGE_LENGTH);
                            
                            continue;
                        }

                        //Return the chat room you are currently in
                        if(strcmp(client_message, "/where") == 0){
                            sprintf(server_message, "Server: You are currently in chat room #%d", room_id);
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                            continue;
                        }

                        //Return the room number that has the user
                        if(strncmp(client_message, "/where ", command_length = 7) == 0){

                            char *target_name = NULL;

                            //Get username from client message
                            get_username_and_passwords(command_length, client_message, &target_name, NULL, NULL);

                            //Check if the username is valid
                            if(!is_username_valid(target_name, server_message)){
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }     

                            //Assume user is not on the server
                            sprintf(server_message, "Server: \"%s\" is currently not on the server", target_name);

                            //Look for user and change the message if located
                            for(int i = 0; i < MAX_ROOMS; i++){
                                if(get_user(i, target_name) != NULL){
                                    sprintf(server_message, "Server: \"%s\" is currently in chat room #%d", target_name, i);
                                    break;
                                }
                            }

                            //Inform client about the specified user
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);

                            continue;
                        }

                        //Return the client's IP address and port
                        if(strcmp(client_message, "/whois") == 0){

                            //Setup "/whois" command with the client's own username
                            client_message[6] = ' ';
                            client_message[7] = '\0';
                            strcat(client_message, username);

                            //Fallthrough to the targeted /whois command
                        }

                        //Return the targeted user's IP address and port
                        if(strncmp(client_message, "/whois ", command_length = 7) == 0){

                            char *target_name = NULL;

                            //Check if client isn't an admin
                            if(!user->is_admin){
                                sprintf(server_message, "Server: Only server admins can use the /whois command");
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Get username from client's message
                            get_username_and_passwords(command_length, client_message, &target_name, NULL, NULL);
                                                  
                            //Check if the username is valid
                            if(!is_username_valid(target_name, server_message)){
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Get user from active_users hash table
                            table_entry_t *target = get_user(room_id, target_name);
                            if(target == NULL){
                                //Username does not exist
                                sprintf(server_message, "Server: The user \"%s\" does not exist", target_name);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }
                            
                            if(strcmp(target_name, username) == 0){
                                sprintf(server_message, "Server: Your address is %s:%d", target->ip, target->port);
                            }else{
                                sprintf(server_message, "Server: The address of \"%s\" is %s:%d", target_name, target->ip, target->port);
                            }
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);

                            continue;
                        }

                        //Inform client of /kick usage
                        if(strcmp(client_message, "/kick") == 0){
                            sprintf(server_message, "Server: Type \"/kick <username>\" to kick users");
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1); 
                            continue;
                        }

                        //Kick specified user from the server
                        if(strncmp(client_message, "/kick ", command_length = 6) == 0){
                           
                            char *target_name = NULL;

                            //Check if client isn't an admin
                            if(!user->is_admin){
                                sprintf(server_message, "Server: Only server admins can use the /kick command");
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Get username from client's message
                            get_username_and_passwords(command_length, client_message, &target_name, NULL, NULL);

                            //Check if the username is valid
                            if(!is_username_valid(target_name, server_message)){
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Prevent client from kicking themself
                            if(strcmp(username, target_name) == 0){
                                sprintf(server_message, "Server: Using /kick on yourself is prohibited");
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Look for user and perform the kick if located
                            int target_room;
                            table_entry_t *targeted_user;
                            for(target_room = 0; target_room < MAX_ROOMS; target_room++){
                                if((targeted_user = get_user(target_room, target_name)) != NULL){

                                    //Get tmp's hh.next for hash table itteration if removing tmp
                                    if(tmp == targeted_user){
                                        tmp = tmp->hh.next; //Avoids accessing removed user
                                    }

                                    //Inform targeted_user that they have been kicked
                                    sprintf(server_message, "Server: You have been kicked from the server");
                                    send_message(targeted_user->socket_fd, server_message_prefixed, strlen(server_message_prefixed) + 1);

                                    //Remove client entry from server
                                    remove_user(target_room, targeted_user);

                                    //Set who_message for rebuild
                                    who_message[target_room][0] = '\0';

                                    break;
                                }
                            }

                            if(targeted_user != NULL){
                                //Print kick message to server's terminal
                                printf("**%s in room #%d kicked from the server**\n", target_name, target_room);

                                //Inform the chat room about the kick
                                sprintf(server_message, "Server: \"%s\" has been kicked from the server", target_name);
                                send_message_to_all(target_room, server_message_prefixed, strlen(server_message_prefixed) + 1);

                                //Also inform client if they are in a different room or the lobby
                                if(room_id != target_room || target_room == LOBBY_ROOM_ID){
                                    send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                }
                            }else{
                                //Inform client that user was not found
                                sprintf(server_message, "Server: \"%s\" is currently not on the server", target_name);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                            }
                            
                            continue;
                        }

                        //Inform client of /register usage
                        if(strcmp(client_message, "/register") == 0){
                            sprintf(server_message, "Server: Type \"/register <username> <password> <password>\" to register");
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1); 
                            continue;
                        }

                        //Register username in user database
                        if(strncmp(client_message, "/register ", command_length = 10) == 0){

                            char *new_name = NULL;
                            char *password = NULL;
                            char *password2 = NULL;
                            char hashed_password[crypto_pwhash_STRBYTES];
                            char *error_message = NULL;
                            char *has_result = NULL;

                            //Get username and passwords from client's message
                            get_username_and_passwords(command_length, client_message, &new_name, &password, &password2);

                            //Check if the username is valid or restricted
                            if(!is_username_valid(new_name, server_message) || !is_username_restricted(new_name, server_message)){
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }       

                            //Check if passwords are valid
                            if(!are_passwords_valid(password, password2, server_message)){
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;  
                            }

                            //Hash password with libsodium
                            if (crypto_pwhash_str(hashed_password, password, strlen(password), PWHASH_OPSLIMIT, PWHASH_MEMLIMIT) != 0) {
                                fprintf(stderr, "Ran out of memory during hash function\n");
                                exit(EXIT_FAILURE);
                            }
                              
                            //Check if username already exists in database
                            snprintf(query, QUERY_LENGTH, "SELECT id FROM users WHERE id = '%s';", new_name);
                            status = sqlite3_exec(user_db, query, callback, &has_result, &error_message);
                            if(status != SQLITE_OK){
                                fprintf(stderr, "SQL query error: %s\n", error_message);
                                sqlite3_free(error_message);
                            }else if(has_result){
                                
                                //Check if client is currently the registered database user
                                if(strcmp(username, new_name) == 0){

                                    //Change password for the registered user
                                    snprintf(query, QUERY_LENGTH, "UPDATE users SET password = '%s' WHERE id = '%s';", hashed_password, username);
                                    status = sqlite3_exec(user_db, query, callback, NULL, &error_message);
                                    if(status != SQLITE_OK){
                                        fprintf(stderr, "SQL query error: %s\n", error_message);
                                        sqlite3_free(error_message);
                                    }else{
                                        //Print password change message to server's terminal
                                        printf("**%s on socket %d changed their password**\n", username, client_socket);
                                        
                                        //Inform client of password change
                                        sprintf(server_message, "Server: Your username password has been changed");
                                        send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                    }

                                }else{
                                    //Inform client that username is already registered
                                    sprintf(server_message, "Server: The username \"%s\" is already registered", new_name);
                                    send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                }

                            }else{

                                //Register username into database
                                snprintf(query, QUERY_LENGTH, "INSERT INTO users(id, password, type) VALUES('%s', '%s', 'user');", new_name, hashed_password);
                                status = sqlite3_exec(user_db, query, callback, NULL, &error_message);
                                if(status != SQLITE_OK){
                                    fprintf(stderr, "SQL query error: %s\n", error_message);
                                    sqlite3_free(error_message);
                                }else{
                                    //Print username registration message to server's terminal
                                    printf("**%s on socket %d registered username %s**\n", username, client_socket, new_name);

                                    //Inform client of username registration
                                    sprintf(server_message, "Server: You have registered the username \"%s\"", new_name);
                                    send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                }

                            }

                            //Clear the plain-text passwords from memory
                            memset(client_message, 0, MESSAGE_LENGTH);

                            continue;
                        }

                        //Trigger server shutdown
                        if(strcmp(client_message, "/die") == 0){

                            //Check if user isn't an admin
                            if(!user->is_admin){
                                sprintf(server_message, "Server: Only server admins can use the /die command");
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Flag server for shutdown
                            pthread_mutex_lock(&shutdown_lock);
                            shutdown_server = true;
                            pthread_mutex_unlock(&shutdown_lock);
                            
                            continue;
                        }

                        //Inform client of /admin usage
                        if(strcmp(client_message, "/admin") == 0){
                            sprintf(server_message, "Server: Type \"/admin <username>\" to change account type");
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1); 
                            continue;
                        }

                        //Change account type of targeted user
                        if(strncmp(client_message, "/admin ", command_length = 7) == 0){

                            char *target_name = NULL;
                            char *user_type = NULL;
                            char *error_message = NULL;
                            char type_change[6] = {'\0'};

                            //Check if client isn't an admin (Allow usage for all admin accounts)
                            /*if(!user->is_admin){
                                sprintf(server_message, "Server: Only server admins can use the /admin command");
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }*/

                            //Check if client isn't the master admin (Allow usage for master admin account only)
                            if(strcmp(username, "Admin") != 0){
                                sprintf(server_message, "Server: Only the \"Admin\" account can use the /admin command");
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Get username from client's message
                            get_username_and_passwords(command_length, client_message, &target_name, NULL, NULL);

                            //Check if the username is valid
                            if(!is_username_valid(target_name, server_message)){
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }   

                            //Check if client is the targeted user
                            if(strcmp(username, target_name) == 0){
                                //Inform client that changing their own account is prohibited
                                sprintf(server_message, "Server: Chaning your own account type is prohibited");
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Check if username is registered in database
                            snprintf(query, QUERY_LENGTH, "SELECT type FROM users WHERE id = '%s';", target_name);
                            status = sqlite3_exec(user_db, query, callback, &user_type, &error_message);
                            if(status != SQLITE_OK){
                                fprintf(stderr, "SQL query error: %s\n", error_message);
                                sqlite3_free(error_message);
                                continue;
                            }

                            if(user_type){
                                
                                //Get the account type to switch to
                                if(strcmp(user_type, "admin") == 0){
                                    strcpy(type_change, "user");
                                }else{
                                    strcpy(type_change, "admin");
                                }

                                free(user_type);

                                //Switch targeted user's account type in database
                                snprintf(query, QUERY_LENGTH, "UPDATE users SET type = '%s' WHERE id = '%s';", type_change, target_name);
                                status = sqlite3_exec(user_db, query, callback, NULL, &error_message);
                                if(status != SQLITE_OK){
                                    fprintf(stderr, "SQL query error: %s\n", error_message);
                                    sqlite3_free(error_message);
                                    continue;
                                }

                                //Look for user on server and change account type if located
                                table_entry_t *user = NULL;
                                for(int i = 0; i < MAX_ROOMS; i++){
                                    if((user = get_user(i, target_name)) != NULL){

                                        //Switch account type
                                        user->is_admin = !user->is_admin;

                                        //Inform targeted user of account type change
                                        sprintf(server_message, "Server: Your account has changed to \"%s\" type", type_change);
                                        send_message(user->socket_fd, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                        
                                        break;
                                    }
                                }

                                //Print account type change message to server's terminal
                                printf("**Account \"%s\" changed to %s type**\n", target_name, type_change);
                                
                                //Inform client of account type change
                                sprintf(server_message, "Server: Account \"%s\" changed to \"%s\" type", target_name, type_change);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);

                            }else{
                                //Inform client that the targeted user is not registered
                                sprintf(server_message, "Server: The username \"%s\" is not registered", target_name);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                            }

                            continue;
                        }

                        sprintf(server_message, "Server: \"%s\" is not a valid command", client_message);
                        send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);

                    }else if(client_message[0] == '\0'){// || client_message[0] == '\r' || client_message[0] == '\n'){
                        /* ----------------------------- */
                        /* Ignore client's empty message */
                        /* ----------------------------- */
                    }else{

                        /* ----------------------- */
                        /* Handle spamming clients */
                        /* ----------------------- */

                        pthread_mutex_lock(&spam_lock);
                        if(spam_timeout[i] != 0){ 
                            //Client currently has a timeout period
                            sprintf(server_message, "Spam Timeout: Please wait %d seconds", spam_timeout[i]);
                            pthread_mutex_unlock(&spam_lock);
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                            continue;
                        }else if(spam_message_count[i] > SPAM_MESSAGE_LIMIT){ 
                            //Give client a timeout period
                            spam_timeout[i] = SPAM_TIMEOUT_LENGTH;
                            pthread_mutex_unlock(&spam_lock);
                            sprintf(server_message, "Spam Timeout: Please wait %d seconds", SPAM_TIMEOUT_LENGTH);
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                            continue;
                        }

                        //Increment spam message count for client
                        spam_message_count[i]++;
                        pthread_mutex_unlock(&spam_lock);


                        /* -------------------------------------- */
                        /* Send client's message to targeted user */
                        /* -------------------------------------- */
                        if(client_message[0] == '@'){

                            char target_username[USERNAME_LENGTH];
                            int target_username_length = strcspn(client_message + 1, " ");
                            if(target_username_length > USERNAME_LENGTH - 1){
                                //Username is too long
                                sprintf(server_message, "Server: Username is too long (max %d characters)", USERNAME_LENGTH - 1);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Copy targeted username from client's message
                            strncpy(target_username, client_message + 1, target_username_length);
                            target_username[target_username_length] = '\0'; //Null terminate username

                            //Force first letter to be uppercase
                            target_username[0] = toupper(target_username[0]);

                            //Look for the user in all chat rooms
                            table_entry_t *target_user = NULL;
                            for(int i = 0; i < MAX_ROOMS; i++){
                                if((target_user = get_user(i, target_username)) != NULL){
                                    break;
                                }
                            }

                            //Inform client if user was not found
                            if(target_user == NULL){
                                sprintf(server_message, "Server: The user \"%s\" does not exist", target_username);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Remove '@' character, username, and empty space from client's message
                            char *message = client_message + 1 + target_username_length + 1;
                            recv_status -= (1 + target_username_length + 1);

                            //Check if message to user is blank
                            if(message[0] == '\0' || message[-1] != ' '){
                                sprintf(server_message, "Server: The message to \"%s\" was blank", target_username);
                                send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                                continue;
                            }

                            //Add sender's username to message
                            message = add_username_to_message(message, username, "> ");
                            size_t additional_length = strlen(username) + 3; //Add three for 0x02 and "> "
        
                            //Send message to target user and sender
                            send_message(target_user->socket_fd, message, recv_status + additional_length);
                            if(target_user->socket_fd != client_socket){
                                send_message(client_socket, message, recv_status + additional_length);
                            }

                            free(message);
                            continue;
                        }

                        //Inform client they aren't in a chat room
                        if(room_id == LOBBY_ROOM_ID){
                            sprintf(server_message, "Server: You're not in a chat room - Use the /join command");
                            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
                            continue;
                        }

                        /* ---------------------------------- */
                        /* Send client's message to all users */
                        /* ---------------------------------- */            
                        
                        //Add sender's username to message
                        char *message = add_username_to_message(client_message, username, ": ");      
                        size_t additional_length = strlen(username) + 3; //Add three for 0x02 and ": "       

                        //Print client's message to server console
                        print_time();
                        printf("#%d ", room_id);
                        printf("%s\n", message + 1); //Add one to skip MESSAGE_START character

                        //Send message to all clients
                        send_message_to_all(room_id, message, recv_status + additional_length);

                        //SEND LOAD TEST//
                        /*send_message_to_all(message, recv_status + additional_length);
                        send_message_to_all(message, recv_status + additional_length);
                        send_message_to_all(message, recv_status + additional_length);
                        send_message_to_all(message, recv_status + additional_length);
                        send_message_to_all(message, recv_status + additional_length);
                        */
                        free(message);
                    }
                }
            }
        }

        pthread_mutex_lock(&shutdown_lock);
        if(shutdown_server){
            pthread_mutex_unlock(&shutdown_lock);
            break;
        }
        pthread_mutex_unlock(&shutdown_lock);

    }

    /* -------------------- */
    /* Shutting down server */
    /* -------------------- */

    //Create server shutdown message
    sprintf(server_message, "Server: The server has been shutdown by an admin");

    //Close client sockets and delete/free users in hash table
    table_entry_t *user, *tmp;
    for(int room_id = 0; room_id < MAX_ROOMS; room_id++){
        HASH_ITER(hh, active_users[room_id], user, tmp){ //Deletion-safe itteration
            client_socket = user->socket_fd;
            send_message(client_socket, server_message_prefixed, strlen(server_message_prefixed) + 1);
            status = close(client_socket);
            check_status(status, "Error closing client socket");
            delete_user(room_id, user);
        }
    }

    //Free who_message strings
    for(int i = 0; i < MAX_ROOMS; i++){
        free(who_message[i]);
    }

}

int send_message(int socket, char *message, int message_length){

    int bytes_sent = 0;

    while(message_length){
        bytes_sent = send(socket, message, message_length, 0);
        if(bytes_sent == -1){
            fprintf(stderr, "Error sending message to socket %d: %s\n", socket, strerror(errno));
            return bytes_sent;
        }
        message += bytes_sent; //Point to the remaining portion that was not sent
        message_length -= bytes_sent; //Calculate the remaining bytes to be sent
    }

    return bytes_sent;
}

int send_message_to_all(int room_id, char *message, int message_length){

    //Prevent messages from being sent to everyone in the lobby room
    if(room_id == LOBBY_ROOM_ID){
        return -1;
    }

    int status = 0;
    table_entry_t *s;

    for(s = active_users[room_id]; s != NULL; s = s->hh.next) {
        status = send_message(s->socket_fd, message, message_length);                     
    }                                                            

    return status;
}


char *add_username_to_message(char *message, char *username, char *suffix){
//NOTE: Calling function must call free on the allocated memory

    int length = 1 + USERNAME_LENGTH + strlen(suffix) + MESSAGE_LENGTH + 1;
    char *message_result = malloc(length);
    if(message_result == NULL){
        fprintf(stderr, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    
    //Add a control character to start of message so we know when it's a new message
    message_result[0] = MESSAGE_START;
    message_result[1] = '\0';
    strcat(message_result, username);
    strcat(message_result, suffix);
    strcat(message_result, message);
    message_result[length - 1] = '\0'; //Ensure NULL termination
    return message_result;
}

void print_time(){
    time_t raw_time = time(NULL);
    struct tm *cur_time;

    //Get local time
    time(&raw_time);
    cur_time = localtime(&raw_time);  

    //Print time to terminal
    printf("%02d:%02d ", cur_time->tm_hour, cur_time->tm_min);  
}

int check_status(int status, char *error){
    if(status == -1){
        perror(error);
        exit(EXIT_FAILURE);
    }
    return status;
}

void get_username_and_passwords(int cmd_length, char *client_message, char **new_name, char **password, char **password2){
    
    //Skip over command in client's message
    *new_name = client_message + cmd_length;

    //Force the first letter to be uppercase
    (*new_name)[0] = toupper((*new_name)[0]);

    if(password == NULL){return;} //Calling function doesn't want password

    //Check if the user entered a password
    *password = memchr(*new_name, ' ', USERNAME_LENGTH);
    if(*password != NULL){

        //Null terminate username and get pointer to password
        (*password)[0] = '\0';
        (*password)++;

        if(password2 == NULL){return;} //Calling function doesn't want a second password

        //Check if the user entered a second password
        *password2 = memchr(*password, ' ', USERNAME_LENGTH);
        if(*password2 != NULL){

            //Null terminate previous password and get pointer to next password
            (*password2)[0] = '\0';
            (*password2)++;
        }
    }
}

int is_password_valid(char *password, char *error_message){

    //Check if password is too long
    if(!memchr(password, '\0', PASSWORD_LENGTH_MAX)){
        sprintf(error_message, "Server: Password is too long (max %d characters)", PASSWORD_LENGTH_MAX - 1);
        return 0;
    }
    //Check if password has any whitespace
    if(strpbrk(password, " \t\n\v\f\r")){
        sprintf(error_message, "Server: Passwords with spaces are restricted");
        return 0;                            
    }
    //Check if password is too short
    if(memchr(password, '\0', PASSWORD_LENGTH_MIN)){
        sprintf(error_message, "Server: Password is too short (min %d characters)", PASSWORD_LENGTH_MIN);
        return 0; 
    }

    return 1;
}

int are_passwords_valid(char *password, char *password2, char *error_message){

    //Check if password is valid
    if(!is_password_valid(password, error_message)){
        return 0;
    }
    //Check if password2 exists
    if(password2 == NULL){
        sprintf(error_message, "Server: The entered command requires the password be repeated");
        return 0;
    }
    //Check if password2 is valid
    if(!is_password_valid(password2, error_message)){
        return 0;
    }
    //Check is both passwords match
    if(strcmp(password, password2) != 0){
        sprintf(error_message, "Server: The two entered passwords do not match");
        return 0;
    }
    
    return 1;
}

int is_username_valid(char *username, char *error_message){

    //Check if username exists
    if(username == NULL){
        sprintf(error_message, "Server: The entered command requires a username");
        return 0;
    }
    //Check if username is too long
    if(!memchr(username, '\0', 16)){
        sprintf(error_message, "Server: Username is too long (max %d characters)", USERNAME_LENGTH - 1);
        return 0;
    }                   
    //Check if username has any whitespace
    if(strpbrk(username, " \t\n\v\f\r")){
        sprintf(error_message, "Server: Usernames with spaces are restricted");
        return 0;                            
    }
    //Check if username is blank
    if(strcmp(username, "") == 0){
        sprintf(error_message, "Server: Blank usernames are restricted");
        return 0;                              
    }

    return 1;
}

int is_username_restricted(char *username, char *error_message){
    
    char *restricted_contains[] = {"Admin", "Server", "Client", "Administrator", "Moderator"};
    char *restricted_exact[] = {"Empty"};

    //Allow restricted usernames that are registered in database and password protected
    if(strcasecmp(username, "Admin") == 0){
        return 1;
    }

    //Check if username contains a restricted keyword
    for(int i = 0; i < sizeof(restricted_contains) / sizeof(restricted_contains[0]); i++){
        if(strncasecmp(username, restricted_contains[i], strlen(restricted_contains[i])) == 0){
            sprintf(error_message, "Server: Usernames containing \"%s\" are restricted", restricted_contains[i]);
            return 0;  
        }
    }

    //Check if username is a restricted keyword
    for(int i = 0; i < sizeof(restricted_exact) / sizeof(restricted_exact[0]); i++){
        if(strcasecmp(username, restricted_exact[i]) == 0){
            sprintf(error_message, "Server: Username \"%s\" is restricted", username);
            return 0;  
        }
    }

    return 1;
}

void rebuild_who_message(char** who_message, int room_id){

    size_t who_message_length;

    //Check if the list of users needs to be rebuilt
    if(who_message[room_id][0] == '\0'){

        //Insert MESSAGE_START character
        who_message[room_id][0] = MESSAGE_START;
        //sprintf(who_message[room_id] + 1, "Server: Room #%d ", room_id);
        sprintf(who_message[room_id] + 1, "Room #%02d: ", room_id);
        
        //Check if chat room has users
        int room_user_count = HASH_COUNT(active_users[room_id]);
        if(room_user_count == 0){
            strcat(who_message[room_id], "Empty");
        }else{

            //strcat(who_message[room_id], "has;");

            //Get who_message string length - Add extra 1 for null character
            who_message_length = strlen(who_message[room_id]) + (room_user_count * USERNAME_LENGTH) + 1;

            //Allocate memory for the string if it's longer than initial allocated size
            if(who_message_length > WHO_LENGTH){
                printf("realloc to %lu\n", who_message_length);
                char *new_ptr = realloc(who_message[room_id], who_message_length);
                if(new_ptr == NULL){
                    fprintf(stderr, "Error allocating memory for who_message\n");
                    exit(0);
                }
                who_message[room_id] = new_ptr;
            } 

            //Itterate through the hash table and append usernames
            table_entry_t *s;
            for(s=active_users[room_id]; s != NULL; s = s->hh.next) {
                strcat(who_message[room_id], s->id);
                strcat(who_message[room_id], " ");
            }

        }
    }
}

void remove_user(int room_id, table_entry_t *user){

    int i = user->index;
    
    //Clear spam timeout and message count so new users using the same spot aren't affected
    pthread_mutex_lock(&spam_lock);
    spam_timeout[i] = 0;
    spam_message_count[i] = 0;
    pthread_mutex_unlock(&spam_lock);

    //Close the client socket
    check_status(close(user->socket_fd), "Error closing client socket");

    //Set FD to ignore state, decrement socket count, and set who_message for rebuild
    socket_fds[i].fd = -1;
    socket_count--;

    //Remove user from active_user hash table
    delete_user(room_id, user);
}

void add_user(int room_id, char *username, size_t index, bool is_admin, int client_fd, char *ip, unsigned short port){
    table_entry_t *s;
    s = malloc(sizeof(table_entry_t));
    if(s == NULL){
        perror("Error allocating hash table memory for new user");
        exit(EXIT_FAILURE);
    }
    strcpy(s->id, username);
    s->index = index;
    s->is_admin = is_admin;
    s->socket_fd = client_fd;
    strcpy(s->ip, ip);
    s->port = port;
    HASH_ADD_STR(active_users[room_id], id, s);  /* id: name of key field */
    HASH_SRT(hh, active_users[room_id], id_compare); 
}

table_entry_t *get_user(int room_id, char *username){
    table_entry_t *user = NULL;
    HASH_FIND_STR(active_users[room_id], username, user);  /* user: output pointer */
    return user;
}

void change_username(int room_id, table_entry_t *user, char *username){
    add_user(room_id, username, user->index, user->is_admin, user->socket_fd, user->ip, user->port);
    delete_user(room_id, user);
}

void delete_user(int room_id, table_entry_t *user) {
    HASH_DEL(active_users[room_id], user);  /* user: pointer to deletee */
    free(user);             /* optional; it's up to you! */
}

int id_compare(table_entry_t *a, table_entry_t *b){
    return (strcasecmp(a->id, b->id));
}

static int callback(void *result, int argc, char **argv, char **azColName){
    
    /*//DEBUG PRINT
    for(int i = 0; i < argc; i++){
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }*/

    if(result != NULL){
        *((char **) result) = strdup(argv[0] ? argv[0] : "NULL");
    }

    return 0;
}