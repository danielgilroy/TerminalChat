CC = gcc
CFLAGS = -I.

chatServer: chatServer.c
	$(CC) -g -O0 -Wall -pedantic -o chatServer chatServer.c -lpthread -lsqlite3 -lsodium