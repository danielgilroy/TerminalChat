#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcpClient.h"

#define PORT_NUMBER 9002
#define MESSAGE_LENGTH 256

int network_socket;

int joinServer(char *response){

    int status;
    //char server_response[MESSAGE_LENGTH];

    //Specify an address and port for the socket to use
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT_NUMBER);
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);  //sin_addr is a "struct in_addr" and contains "uint32_t s_addr"
    /*if(inet_pton(AF_INET, "127.0.0.1", &(server_address.sin_addr)) <= 0){ //Converts IP string to type "struct in_addr"
        fprintf(stderr, "Error converting IP address string to struct in_addr");
        exit(0);
    }*/
    memset(server_address.sin_zero, 0, sizeof(server_address.sin_zero));

    //Create Socket
    network_socket = socket(PF_INET, SOCK_STREAM, 0);
    checkStatus(network_socket);

    //Perform the connection using the socket and address struct
    status = connect(network_socket, (struct sockaddr *) &server_address, sizeof(server_address));
    
    //Check for error with the connection
    if(status){
        closeSocket(network_socket);
        return status;
    }

    //Recieve welcome message from the server
    status = recv(network_socket, response, MESSAGE_LENGTH, 0);
    checkStatus(status);

    return status;
}

int receiveMessage(char *message, int message_length){

    int recv_status;

    recv_status = recv(network_socket, message, message_length, 0);

    if(recv_status <= 0) {
        closeSocket(network_socket);
    }
    
    return recv_status;
}

int sendMessage(char *message, int message_length){

    int bytes_sent;

    if(!strcmp(message, "/exit\n") || !strcmp(message, "/quit")){
        bytes_sent = closeSocket(network_socket);
        checkStatus(bytes_sent);
    }else{
        do{
            bytes_sent = send(network_socket, message, message_length, 0);
            checkStatus(bytes_sent);
            if(bytes_sent < 0){
                break;
            }
            message += bytes_sent; //Point to the remaining portion that was not sent
            message_length -= bytes_sent; //Calculate the remaining bytes to be sent
        }while(message_length);
    }

    return bytes_sent;
}

int closeSocket(int socket){

    //Close the socket
    int status = close(socket);
    checkStatus(status);

    return status;
}

void checkStatus(int status){
    if(status == -1){
        fprintf(stderr, "Error: %s\n", strerror(errno));
    }
}