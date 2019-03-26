CC=gcc
CFLAGS=-I.

chatServer: chatServer.c
	$(CC) -o chatServer chatServer.c -lncurses -lpthread