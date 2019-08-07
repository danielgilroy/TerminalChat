CC = gcc
CFLAGS = -I.
DEPS = chatClient.h tcpClient.h
OBJ = chatClient.o tcpClient.o
DEBUG = -g -O0

%.o: %.c $(DEPS)
	$(CC) $(DEBUG) -c -o $@ $< $(CFLAGS)

chatClient: $(OBJ)
	$(CC) $(DEBUG) -Wall -pedantic -o $@ $^ $(CFLAGS) -lncurses -lpthread

clean:
	rm chatClient $(OBJ)