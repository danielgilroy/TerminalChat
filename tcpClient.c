#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "tcpClient.h"

int network_socket;

int joinServer(char *response){

    int status;

    //Create Socket
    network_socket = socket(AF_INET, SOCK_STREAM, 0);
    checkStatus(network_socket);

    //Specify an address and port for the socket to use
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(9002);
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);

    //Perform the connection using the socket and address struct
    status = connect(network_socket, (struct sockaddr *) &server_address, sizeof(server_address));
    
    //Check for error with the connection
    if(status){
        //fprintf(stderr, "There was an error making a connection to the remote socket\n\n");
        closeSocket(network_socket);
        return status;
    }

    //Recieve welcome message from the server
    char server_response[256];
    status = recv(network_socket, &server_response, sizeof(server_response), 0);
    checkStatus(status);

    //Copy server response into chat_client buffer to be printed
    strcpy(response, server_response);

    return status;
}

int receiveMessage(char *message, int message_length){

    int status;
    status = recv(network_socket, message, message_length, 0);

    if(status <= 0) {
        closeSocket(network_socket);
    }

    return status;
}

int sendMessage(char *message, int message_length){

    int status;

    if(!strcmp(message, "/exit\n")){
        status = closeSocket(network_socket);
    }else{
        status = send(network_socket, message, message_length, 0);
        checkStatus(status);
    }

    return status;
}

int closeSocket(int socket){

    //Close the socket
    //To Do: Review difference between close and shutdown
    //if(shutdown(network_socket, SHUT_RDWR)){
    int status = close(socket);
    checkStatus(status);

    return status;
}

void checkStatus(int status){
    if(status == -1){
        fprintf(stderr, "Error: %s\n", strerror(errno));
    }
}