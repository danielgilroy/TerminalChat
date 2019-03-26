CC=gcc
CFLAGS=-I.
DEPS = tcpClient.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

chat_client: chatClient.o tcpClient.o
	$(CC) -o chatClient chatClient.c tcpClient.c -lncurses -lpthread