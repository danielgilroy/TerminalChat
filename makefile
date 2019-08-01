CC = gcc
CFLAGS = -I.
DEPS = chatServer.h chatServerUtils.h chatServerCommands.h uthash.h
OBJ = chatServer.o chatServerUtils.o chatServerCommands.o

%.o: %.c $(DEPS)
	$(CC) -g -O0 -c -o $@ $< $(CFLAGS)

chatServer: $(OBJ)
	$(CC) -g -O0 -Wall -pedantic -o $@ $^ $(CFLAGS) -lpthread -lsqlite3 -lsodium