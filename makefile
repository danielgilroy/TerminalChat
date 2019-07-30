CC = gcc
CFLAGS = -I.
DEPS = chatServer.h chatServerUtils.h uthash.h
OBJ = chatServer.o chatServerUtils.o

%.o: %.c $(DEPS)
	$(CC) -g -O0 -c -o $@ $< $(CFLAGS)

chatServer: $(OBJ)
	$(CC) -g -O0 -Wall -pedantic -o $@ $^ $(CFLAGS) -lpthread -lsqlite3 -lsodium