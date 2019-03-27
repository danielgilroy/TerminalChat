#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <poll.h>

#define MAX_CLIENTS 4 //Max FD limit on linux is set to 1024 by default

void initializeServer();
void *acceptNewClients(void *);
void *spamFilter();
void processClients();
int sendMessageToAll(char *, int);
void printTime();
void checkStatus(int);

struct pollfd client_fds[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t lock;
char waitingForMutex = 0;

char userNames[MAX_CLIENTS][16];

short spam_message_count[MAX_CLIENTS]; //Spam message counters for each client
short spam_timeout[MAX_CLIENTS]; //Spam timeout for each client
const short spam_message_limit = 10; //Max messages within spam check window
const short spam_timeout_length = 20; //Timeout period for detected spammer
pthread_mutex_t spam_lock;

int main(){

    int status;

    pthread_mutex_init(&lock, NULL);
    pthread_mutex_init(&spam_lock, NULL);

    initializeServer();

    printf("**Shutting down server**\n");
    pthread_mutex_destroy(&lock);
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
    server_address.sin_port = htons(9002);
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);

    //Bind the socket to our specified IP address and port
    status = bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));
    checkStatus(status);

    //Set the socket up to wait for connections
    status = listen(server_socket, 5);
    checkStatus(status);

    //Initialize client fds
    for(int i = 0; i < MAX_CLIENTS; i++){
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
    char server_message[256];
    char user_name[16];

    //Declare the client socket to connect to
    int client_socket;

    printf("**Awaiting clients**\n");

    while(1){

        //Accept a connection from a client
        client_socket = accept(server_socket, NULL, NULL);
        checkStatus(client_socket);
        
        //Add client to global array of client file descriptors
        while(1){
            if(client_fds[index].fd <= 0){
                waitingForMutex = 1;
                pthread_mutex_lock(&lock);
                //puts("-Mutex Locked: New Client-");
                client_fds[index].fd = client_socket;
                pthread_mutex_unlock(&lock);
                waitingForMutex = 0;
                //puts("-Mutex Unlocked: New Client-");
                sprintf(user_name, "Client%d", client_fds[index].fd);
                strcpy(userNames[index], user_name);
                index = (index + 1) % MAX_CLIENTS;
                break;
            } else {
                index = (index + 1) % MAX_CLIENTS;
            }
        }
        
        printf("**Client on socket %d joined the server**\n", client_socket);
        
        //Send the message to the client socket
        sprintf(server_message, "Server: Welcome to the server! You are using socket %d", client_socket);
        status = send(client_socket, server_message, strlen(server_message) + 1, 0);
        checkStatus(status);

        sprintf(server_message, "Server: Client%d has joined the server", client_socket);
        sendMessageToAll(server_message, strlen(server_message) + 1);

        client_count++;

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
        for(int i = 0; i < MAX_CLIENTS; i++){
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
    char client_message[256];
    char spam_message[256];
        
    while(1){
        
        while(waitingForMutex){
            //Wait for priorty thread to finish with mutex lock
        }
        sleep(0.05);
        pthread_mutex_lock(&lock);
        status = poll(client_fds, MAX_CLIENTS, 500);
        pthread_mutex_unlock(&lock);   

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
        for(int i = 0; i < MAX_CLIENTS; i++){

            if(client_fds[i].revents & POLLIN){

                recv_status = recv(client_fds[i].fd, client_message, sizeof(client_message), 0);
                checkStatus(recv_status);

                if(recv_status == 0){

                    //Print message to server terminal
                    printf("**%s on socket %d left the server**\n", userNames[i], client_fds[i].fd);
                    
                    //Print message to chat server
                    sprintf(client_message, "Server: %s has left the server", userNames[i]);
                    sendMessageToAll(client_message, strlen(client_message) + 1);
                    
                    //Close the client socket
                    status = close(client_fds[i].fd);
                    checkStatus(status);
                    client_fds[i].fd = -1;
                    client_count--;
                    continue;
                }

                if(client_message[0] == '/'){

                    //Process server commands

                    //Change client's username
                    if(strncmp(client_message, "/nick ", 6) == 0){
                        printf("**%s on socket %d changed username to ", userNames[i], client_fds[i].fd);
                        sprintf(spam_message, "Server: %s has changed their name to ", userNames[i]);

                        strncpy(userNames[i], client_message + 6, 15);
                        userNames[i][15] = '\0'; //Null terminate username

                        printf("%s**\n", userNames[i]);
                        strcat(spam_message, userNames[i]);
                        sendMessageToAll(spam_message, strlen(spam_message) + 1);
                    }

                    continue;
                }else if(client_message[0] == '\r' || client_message[0] == '\n' || client_message[0] == '\0'){
                    //Client message is empty so ignore it
                    continue;
                }else{

                    //Check spam_message_count to ensure client isn't spamming
                    pthread_mutex_lock(&spam_lock);
                    if(spam_timeout[i] != 0){ //Client currently has timeout period
                        sprintf(spam_message, "Spam Timeout: Please wait %d seconds", spam_timeout[i]);
                        pthread_mutex_unlock(&spam_lock);
                        send(client_fds[i].fd, spam_message, strlen(spam_message) + 1, 0);
                        continue;
                    }else if(spam_message_count[i] >= spam_message_limit){ //Give client timeout period
                        spam_timeout[i] = spam_timeout_length;
                        pthread_mutex_unlock(&spam_lock);
                        sprintf(spam_message, "Spam Timeout: Please wait %d seconds", spam_timeout_length);
                        send(client_fds[i].fd, spam_message, strlen(spam_message) + 1, 0);
                        continue;
                    }

                    /* ------------------------ */
                    /* Sending client's message */
                    /* ------------------------ */

                    //Increment message counter for client
                    spam_message_count[i]++;
                    pthread_mutex_unlock(&spam_lock);
                    
                    /* Debug Print */
                    //printf("Received %d characters\n", recv_status);
                    /* ----------- */

                    //Replace ending \n with \0 or ending \r\n with \0\0
                    if(client_message[recv_status-1] == '\n'){
                        client_message[recv_status-1] = '\0';
                        if(client_message[recv_status-2] == '\r'){
                            client_message[recv_status-2] = '\0';
                            recv_status--;
                        }
                    }                    

                    /* Include User Name */
                    char message[280];
                    //sprintf(message, "Client%d: ", client_fds[i].fd); 
                    strncpy(message, userNames[i], 16);
                    strcat(message, ": ");
                    char username_length = strlen(message);
                    strcat(message, client_message);
                    /********************/

                    //Print client's message to server console
                    printTime();
                    printf("%s\n", message);

                    //Send message to all clients
                    //Only send the number of bytes received from recv + username length
                    sendMessageToAll(message, recv_status + username_length);
                
                }

            }
        }

    }
}

int sendMessageToAll(char *message, int message_length){

    int status;

    for(int i = 0; i < MAX_CLIENTS; i++){

        if(client_fds[i].fd <= 0){
            continue;
        }

        status = send(client_fds[i].fd, message, message_length, 0);
        checkStatus(status);
    }

    return status;
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