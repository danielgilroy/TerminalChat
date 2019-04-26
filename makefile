CC=gcc
CFLAGS=-I.

chatServer: chatServer.c
	$(CC) -Wall -pedantic -o chatServer chatServer.c -lncurses -lpthread