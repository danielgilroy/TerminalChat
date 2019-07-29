CC = gcc
CFLAGS = -I.
DEPS = chatClient.h tcpClient.h
OBJ = chatClient.o tcpClient.o

%.o: %.c $(DEPS)
	$(CC) -g -O0 -c -o $@ $< $(CFLAGS)

chatClient: $(OBJ)
	$(CC) -g -O0 -Wall -pedantic -o $@ $^ $(CFLAGS) -lncurses -lpthread