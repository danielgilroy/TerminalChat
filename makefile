CC = gcc
CFLAGS = -I.
DEPS = tcpClient.h

%.o: %.c $(DEPS)
	$(CC) -g -O0 -c -o $@ $< $(CFLAGS)

chat_client: chatClient.o tcpClient.o
	$(CC) -g -O0 -Wall -pedantic -o chatClient chatClient.c tcpClient.c -lncurses -lpthread