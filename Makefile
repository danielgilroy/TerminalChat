CC = gcc
CFLAGS = -I.
DEPS = chatServer.h chatServerUtils.h chatServerCommands.h
OBJ = chatServer.o chatServerUtils.o chatServerCommands.o
DEBUG = -g -O0

%.o: %.c $(DEPS)
	$(CC) $(DEBUG) -c -o $@ $< $(CFLAGS)

chatServer: $(OBJ)
	$(CC) $(DEBUG) -Wall -pedantic -o $@ $^ $(CFLAGS) -lpthread -lsqlite3 -lsodium

clean:
	rm chatServer $(OBJ)
