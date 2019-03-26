#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

int joinServer(char *);
int receiveMessage(char *, int);
int sendMessage(char *, int);
int closeSocket(int);
void checkStatus(int);

#endif