#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <poll.h>

#include "uthash.h"

#define PORT_NUMBER 9002
#define POLL_TIMEOUT 500 //Poll timeout in milliseconds: Reduce this if joining chat takes too long
#define MAX_CLIENTS 4 //1000 //Max FD limit on linux is set to 1024 by default
#define USERNAME_LENGTH 16
#define MESSAGE_LENGTH 256

void initializeServer();
void *acceptNewClients(void *);
void *spamFilter();
void processClients();
int sendMessage(int, char *, int);
int sendMessageToAll(char *, int);
char *addUsernameToMessage(char *, char *);
void printTime();
void checkStatus(int);
void add_username(char *, int);
void replace_username(char *, char *, int);
struct table_entry *find_username(char *);
void delete_username(struct table_entry *);
int id_compare(struct table_entry *, struct table_entry *);

struct pollfd client_fds[MAX_CLIENTS];
int client_count = 0;
char waitingForMutex = 0;
pthread_mutex_t fd_lock;
pthread_mutex_t cc_lock;

char usernames[MAX_CLIENTS][USERNAME_LENGTH];

struct table_entry {
    char id[USERNAME_LENGTH];                    /* key */
    int client_fd;
    UT_hash_handle hh;         /* makes this structure hashable */
};

struct table_entry *username_to_fd = NULL; 

short spam_message_count[MAX_CLIENTS]; //Spam message counters for each client
short spam_timeout[MAX_CLIENTS]; //Spam timeout for each client
const short spam_message_limit = 10; //Max messages within spam check window
const short spam_timeout_length = 20; //Timeout period for detected spammer
pthread_mutex_t spam_lock;

int main(){

    int status;

    pthread_mutex_init(&fd_lock, NULL);
    pthread_mutex_init(&cc_lock, NULL);
    pthread_mutex_init(&spam_lock, NULL);

    initializeServer();

    printf("**Shutting down server**\n");
    pthread_mutex_destroy(&fd_lock);
    pthread_mutex_destroy(&cc_lock);
    pthread_mutex_destroy(&spam_lock);

    return 0;
}

void initializeServer(){

    int status;

    //Create the server socket to use for a connection
    int server_socket;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    checkStatus(server_socket);

    //Define the server's IP address and port
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT_NUMBER);
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);

    //Bind the socket to our specified IP address and port
    status = bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));
    checkStatus(status);

    //Set the socket up to wait for connections
    status = listen(server_socket, 5);
    checkStatus(status);

    //Initialize client fds
    for(size_t i = 0; i < MAX_CLIENTS; i++){
        client_fds[i].fd = -1;
        client_fds[i].events = POLLIN;
    }
    
    //Create thread for processing new clients
    pthread_t tid;
    pthread_create(&tid, NULL, acceptNewClients, (void *) &server_socket);

    //Create thread for spam filter
    pthread_t spam_tid;
    pthread_create(&spam_tid, NULL, spamFilter, NULL);

    //Call method for receiving client responses
    processClients();

    pthread_join(tid, NULL);
    pthread_join(spam_tid, NULL);

    //Close the server socket
    printf("**Closing server socket**\n");
    status = close(server_socket);
    checkStatus(status);

}

void *acceptNewClients(void *server){

    int status;
    int index = 0;
    int server_socket = *((int *) server);
    char server_message[MESSAGE_LENGTH];
    char user_name[USERNAME_LENGTH];

    //Declare the client socket to connect to
    int client_socket;

    printf("**Awaiting clients**\n");

    while(1){

        //Accept a connection from a client
        client_socket = accept(server_socket, NULL, NULL);
        checkStatus(client_socket);
        
        //Check if server is full
        pthread_mutex_lock(&cc_lock);
        if(client_count >= MAX_CLIENTS){
            pthread_mutex_unlock(&cc_lock);
            printf("**Server has reached the maximum of %d clients**\n", MAX_CLIENTS);
            sprintf(server_message, "Server: The server has reached the maximum of %d clients", MAX_CLIENTS);
            sendMessage(client_socket, server_message, strlen(server_message) + 1);
            status = close(client_socket);
            checkStatus(status);
            continue;
        }else{
            client_count++;
            pthread_mutex_unlock(&cc_lock);
        }
        

        //Find an available spot in the FD array
        while(client_fds[index].fd > 0){
            index = (index + 1) % MAX_CLIENTS;
        }

        //Assign the socket to the client FD
        waitingForMutex = 1;
        pthread_mutex_lock(&fd_lock);
        client_fds[index].fd = client_socket;
        pthread_mutex_unlock(&fd_lock);
        waitingForMutex = 0;

        //Give client a default username based on file descriptor
        sprintf(user_name, "Client%d", client_fds[index].fd);
        strcpy(usernames[index], user_name); //Potenial thread issue without a mutex lock!!!
        add_username(user_name, client_socket);
      
        //Print message to the server's terminal
        printf("**Client on socket %d joined the server**\n", client_socket);
    
        //Send welcome message to the client socket
        sprintf(server_message, "Server: Welcome to the server! You are using socket %d", client_socket);
        sendMessage(client_socket, server_message, strlen(server_message) + 1);

        //Send message to every client letting them know someone joined the server
        sprintf(server_message, "Server: Client%d joined the server", client_socket);
        sendMessageToAll(server_message, strlen(server_message) + 1);

    }
}

void *spamFilter(){

    int current_interval = 0; //Current interval within spam interval window
    const int spam_interval_total = 10; //Interval window for message limit

    while(1){

        sleep(1);
        
        current_interval++;

        //Reset spam message counters to be used in new spam interval window
        if(current_interval % spam_interval_total == 0){
            pthread_mutex_lock(&spam_lock);
            memset(spam_message_count, 0, sizeof(spam_message_count));
            pthread_mutex_unlock(&spam_lock);
            current_interval = 0;
        }

        //Reduce every client's timeout period by one until it's zero
        pthread_mutex_lock(&spam_lock);
        for(size_t i = 0; i < MAX_CLIENTS; i++){
            if(spam_timeout[i] > 0){
                spam_timeout[i]--;
            }
        }
        pthread_mutex_unlock(&spam_lock);
        
    }
}

void processClients(){

    int status;
    int recv_status;
    int8_t changes = 1; //Boolean: Client has left or changed their name
    char client_message[MESSAGE_LENGTH];
    char server_message[MESSAGE_LENGTH];
    char *who_message = NULL;
        
    while(1){
        
        while(waitingForMutex){
            //Wait for priorty thread to finish with mutex lock
        }
        sleep(0.05);
        pthread_mutex_lock(&fd_lock);
        status = poll(client_fds, MAX_CLIENTS, POLL_TIMEOUT);
        pthread_mutex_unlock(&fd_lock);   

        if(status == -1){
            perror("Error");
            continue;
        }else if(status == 0){
            //Timeout occurred: Clients don't have any events or errors
            //printf("Client FDs: %d %d %d %d\n", client_fds[0].fd, client_fds[1].fd, 
            //        client_fds[2].fd, client_fds[3].fd);
            continue;
        }
            
        //Event has occurred: Check all clients for events
        for(size_t i = 0; i < MAX_CLIENTS; i++){
        
            if(client_fds[i].revents & POLLIN){

                recv_status = recv(client_fds[i].fd, client_message, sizeof(client_message), 0);
                checkStatus(recv_status);

                if(recv_status == 0){

                    /* -------------------------- */
                    /* Client has left the server */
                    /* -------------------------- */

                    //Print message to server terminal
                    printf("**%s on socket %d left the server**\n", usernames[i], client_fds[i].fd);
                
                    //Print message to chat server
                    sprintf(client_message, "Server: %s left the server", usernames[i]);
                    sendMessageToAll(client_message, strlen(client_message) + 1);
                    
                    //Remove username from hash table
                    delete_username(find_username(usernames[i]));
                    
                    //Remove username from array
                    usernames[i][0] = '\0';

                    changes = 1;

                    //Close the client socket
                    status = close(client_fds[i].fd);
                    checkStatus(status);
                    client_fds[i].fd = -1;
                    pthread_mutex_lock(&cc_lock);
                    client_count--;
                    pthread_mutex_unlock(&cc_lock);
                    continue;
                }

                if(client_message[0] == '/'){

                    /* ------------------------------- */
                    /* Process client's server command */
                    /* ------------------------------- */

                    //List who's connected to the chat server
                    if(strncmp(client_message, "/who", 5) == 0){
                        
                        char *message_prefix = "Server:";
                        static int count = 0; //Client count since last rebuild of who_message
                        size_t who_message_length;

                        //Check if the list of users needs to be rebuilt
                        pthread_mutex_lock(&cc_lock);
                        if(changes || count != client_count){

                            //Set variables for the next /who command to check
                            count = client_count;
                            pthread_mutex_unlock(&cc_lock);
                            changes = 0;

                            //Allocate memory for the string of users
                            who_message_length = strlen(message_prefix) + (count * USERNAME_LENGTH) + 1 ;
                            char *new_ptr = realloc(who_message, who_message_length);
                            if(new_ptr == NULL){
                                fprintf(stderr, "Error allocating memory for /who function\n");
                                exit(0);
                            }
                            who_message = new_ptr;

                            //Copy prefix message to the string
                            strcpy(who_message, message_prefix);

                            //Sort the hash table so usernames are printed in order
                            HASH_SORT(username_to_fd, id_compare);
                                                    
                            //Itterate through the hash table and append usernames
                            struct table_entry *s;
                            for(s=username_to_fd; s != NULL; s=s->hh.next) {
                                strcat(who_message, " ");
                                strcat(who_message, s->id);
                            }

                        }else{
                            //Unlock mutex that was locked when reading client_count
                            pthread_mutex_unlock(&cc_lock);
                        }

                        //Send message containing current users to the client
                        sendMessage(client_fds[i].fd, who_message, who_message_length);
                        continue; 
                    }

                    //Change username or echo back current one
                    if(strncmp(client_message, "/nick", 5) == 0){
                    
                        if(client_message[5] == '\0'){
                            //Echo back current username
                            sprintf(server_message, "Server: Your username is \"%s\"", usernames[i]);
                            sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                            continue;
                        }

                        char new_name[USERNAME_LENGTH];

                        //Get new name from client's message
                        strncpy(new_name, client_message + 6, USERNAME_LENGTH);

                        //Check if new name is too long
                        if(new_name[15] != '\0'){
                            sprintf(server_message, "Server: Username is too long (max %d characters)", USERNAME_LENGTH - 1);
                            sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                            continue;
                        }

                        //Check if new name has any whitespace
                        if(strpbrk(new_name, " \t\n\v\f\r")){
                            sprintf(server_message, "Server: Usernames with spaces are restricted");
                            sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                            continue;                            
                        }

                        //Check if new name is a restricted name
                        if(strcasecmp(new_name, "Server") == 0){
                            sprintf(server_message, "Server: The username \"%s\" is restricted", new_name);
                            sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                            continue;  
                        }
                        if(strcasecmp(new_name, "") == 0){
                            sprintf(server_message, "Server: Blank usernames are restricted");
                            sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                            continue;                              
                        }

                        //Force the first letter of the name to be uppercase
                        new_name[0] = toupper(new_name[0]);

                        //Check if username is already in use
                        if(find_username(new_name) != NULL){
                            sprintf(server_message, "Server: The username \"%s\" is already in use", new_name);
                            sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                            continue;
                        }
                        
                        //Send message to all clients informing them of the name change
                        printf("**%s on socket %d changed username to %s**\n", usernames[i], client_fds[i].fd, new_name);
                        sprintf(server_message, "Server: %s changed name to %s", usernames[i], new_name);
                        sendMessageToAll(server_message, strlen(server_message) + 1);

                        //Change username in hash table and array
                        replace_username(usernames[i], new_name, client_fds[i].fd);
                        strcpy(usernames[i], new_name);

                        changes = 1;

                        continue;
                    }

                    sprintf(server_message, "Server: \"%s\" is not a valid command", client_message);
                    sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);

                    continue;

                }else if(client_message[0] == '\r' || client_message[0] == '\n' || client_message[0] == '\0'){
                    /* ----------------------------- */
                    /* Ignore client's empty message */
                    /* ----------------------------- */
                    continue;
                }else{

                    /* --------------------------- */
                    /* Check if client is spamming */
                    /* --------------------------- */
                    pthread_mutex_lock(&spam_lock);
                    if(spam_timeout[i] != 0){ 
                        //Client currently has a timeout period
                        sprintf(server_message, "Spam Timeout: Please wait %d seconds", spam_timeout[i]);
                        pthread_mutex_unlock(&spam_lock);
                        sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                        continue;
                    }else if(spam_message_count[i] >= spam_message_limit){ 
                        //Give client a timeout period
                        spam_timeout[i] = spam_timeout_length;
                        pthread_mutex_unlock(&spam_lock);
                        sprintf(server_message, "Spam Timeout: Please wait %d seconds", spam_timeout_length);
                        sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                        continue;
                    }

                    /* ------------------------ */
                    /* Prepare client's message */
                    /* ------------------------ */

                    //Increment spam message count for client
                    spam_message_count[i]++;
                    pthread_mutex_unlock(&spam_lock);

                    //Replace ending \n with \0 or ending \r\n with \0\0
                    if(client_message[recv_status-1] == '\n'){
                        client_message[recv_status-1] = '\0';
                        if(client_message[recv_status-2] == '\r'){
                            client_message[recv_status-2] = '\0';
                            recv_status--;
                        }
                    }     

                    /* -------------------------------------- */
                    /* Send client's message to targeted user */
                    /* -------------------------------------- */
                    if(client_message[0] == '@'){

                        char target_user_name[USERNAME_LENGTH];
                        int target_username_length = strcspn(client_message + 1, " ");
                        if(target_username_length > USERNAME_LENGTH - 1){
                            //Username is too long
                            sprintf(server_message, "Server: Username is too long (max %d characters)", USERNAME_LENGTH - 1);
                            sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                            continue;
                        }

                        strncpy(target_user_name, client_message + 1, target_username_length);
                        target_user_name[target_username_length] = '\0'; //Null terminate username

                        target_user_name[0] = toupper(target_user_name[0]);

                        struct table_entry *target_user = find_username(target_user_name);
                        if(target_user == NULL){
                            //Username does not exist
                            sprintf(server_message, "Server: The user \"%s\" does not exist", target_user_name);
                            sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                            continue;
                        }

                        //Remove '@' character, username, and empty space from client's message
                        char *message = client_message + 1 + target_username_length + 1;
                        recv_status -= (1 + target_username_length + 1);

                        if(message[0] == '\0' || message[-1] != ' '){
                            //Message to user is blank
                            sprintf(server_message, "Server: The message to \"%s\" was blank", target_user_name);
                            sendMessage(client_fds[i].fd, server_message, strlen(server_message) + 1);
                            continue;
                        }

                        //Add sender's username to message
                        message = addUsernameToMessage(message, usernames[i]);
                        size_t additional_length = strlen(usernames[i]) + 2; //Add two for ": "

                        //Send message to target user and sender
                        sendMessage(target_user->client_fd, message, recv_status + additional_length);
                        if(target_user->client_fd != client_fds[i].fd){
                            sendMessage(client_fds[i].fd, message, recv_status + additional_length);
                        }

                        free(message);
                        continue;

                    }

                    /* ---------------------------------- */
                    /* Send client's message to all users */
                    /* ---------------------------------- */            
                    
                    //Add sender's username to message
                    char *message = addUsernameToMessage(client_message, usernames[i]);      
                    size_t additional_length = strlen(usernames[i]) + 2; //Add two for ": "        

                    //Print client's message to server console
                    printTime();
                    printf("%s\n", message);

                    //Send message to all clients
                    sendMessageToAll(message, recv_status + additional_length);
                    free(message);

                }
            }
        }
    }
}

int sendMessage(int socket, char *message, int message_length){

    int status;

    status = send(socket, message, message_length, 0);
    checkStatus(status);

    return status;
}

int sendMessageToAll(char *message, int message_length){

    int status;

    for(size_t i = 0; i < MAX_CLIENTS; i++){

        if(client_fds[i].fd <= 0){
            continue; //Ignore invalid FDs
        }

        status = send(client_fds[i].fd, message, message_length, 0);
        checkStatus(status);
    }

    return status;
}


char *addUsernameToMessage(char *message, char *username){
//NOTE: Calling function must call free on the allocated memory

    char *message_result = malloc(MESSAGE_LENGTH + USERNAME_LENGTH + 2);
    if(message_result == NULL){
        fprintf(stderr, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    strncpy(message_result, username, USERNAME_LENGTH);
    strcat(message_result, ": ");
    strcat(message_result, message);
    return message_result;
}

void printTime(){
    time_t raw_time = time(NULL);
    struct tm *cur_time;

    //Get local time
    time(&raw_time);
    cur_time = localtime(&raw_time);  

    //Print time to terminal
    printf("%02d:%02d ", cur_time->tm_hour, cur_time->tm_min);  
}

void checkStatus(int status){
    if(status == -1){
        //fprintf(stderr, "Error: %s\n", strerror(errno));
        perror("Error"); //Has same function
        exit(EXIT_FAILURE);
    }
}

void add_username(char *username, int client_fd){
    struct table_entry *s;
    s = malloc(sizeof(struct table_entry));
    strcpy(s->id, username);
    s->client_fd = client_fd;
    HASH_ADD_STR(username_to_fd, id, s);  /* id: name of key field */
}

void replace_username(char *old_username, char *username, int client_fd){
    delete_username(find_username(old_username));
    add_username(username, client_fd);
}

struct table_entry *find_username(char *username){
    struct table_entry *s;
    HASH_FIND_STR(username_to_fd, username, s);  /* s: output pointer */
    return s;
}

void delete_username(struct table_entry *user) {
    HASH_DEL(username_to_fd, user);  /* user: pointer to deletee */
    free(user);             /* optional; it's up to you! */
}

int id_compare(struct table_entry *a, struct table_entry *b){
    return (strcasecmp(a->id, b->id));
}
