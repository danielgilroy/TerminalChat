#include "client_tcp.h"

int network_socket;

int join_server(char *ip, unsigned int port, char *response){

    int status;

    //Specify an address and port for the socket to use
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    if(inet_pton(AF_INET, ip, &(server_address.sin_addr)) <= 0){ //Converts IP string to type "struct in_addr"
        strcpy(response, "-Error converting IP address string to struct in_addr-");
        return -1;
    }
    memset(server_address.sin_zero, 0, sizeof(server_address.sin_zero));

    //Create Socket
    network_socket = socket(PF_INET, SOCK_STREAM, 0);
    check_status(network_socket);

    //Perform the connection using the socket and address struct
    status = connect(network_socket, (struct sockaddr *) &server_address, sizeof(server_address));
    
    //Check for error with the connection
    if(status){
        close_socket(network_socket);
        strcpy(response, "        -Error connecting to the chat server-");
        return status;
    }

    //Recieve welcome message from the server
    status = recv(network_socket, response, MESSAGE_LENGTH, 0);
    check_status(status);

    return status;
}

int receive_message(char *message, int message_length){

    int recv_status;

    recv_status = recv(network_socket, message, message_length, 0);

    if(recv_status <= 0) {
        close_socket(network_socket);
    }
    
    return recv_status;
}

int send_message(char *client_message, int client_message_size){

    int bytes_sent;
    int message_size = client_message_size + 2; //Add 2 for start and end characters
    char message[message_size]; 
    char *message_ptr = message;

    //Add a control character to the start and end of the message so the server knows when it's
    //received a complete message since the message may be split up over multiple packets
    message[0] = MESSAGE_START;
    strncpy(message + 1, client_message, client_message_size);
    message[message_size - 2] = MESSAGE_END;
    message[message_size - 1] = '\0';

    if(!strcmp(message, "/exit\n") || !strcmp(message, "/quit")){
        bytes_sent = close_socket(network_socket);
        check_status(bytes_sent);
    }else{
        do{
            bytes_sent = send(network_socket, message_ptr, message_size, 0);
            check_status(bytes_sent);
            if(bytes_sent < 0){
                break;
            }
            message_ptr += bytes_sent; //Point to the remaining portion that was not sent
            message_size -= bytes_sent; //Calculate the remaining bytes to be sent
        }while(message_size);
    }

    return bytes_sent;
}

int close_socket(int socket){

    //Close the socket
    int status = close(socket);
    check_status(status);

    return status;
}

void check_status(int status){
    if(status == -1){
        fprintf(stderr, "Error: %s\n", strerror(errno));
    }
}