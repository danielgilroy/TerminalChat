CC = gcc
CFLAGS = -I.
DEPS = chat_server.h chat_server_utils.h chat_server_commands.h
OBJ = $(OBJDIR)/chat_server.o $(OBJDIR)/chat_server_utils.o $(OBJDIR)/chat_server_commands.o
DEBUG = -g -O0
LIBS = -lpthread -lsqlite3 -lsodium

VPATH = src
OBJDIR = obj

$(OBJDIR)/%.o: %.c $(DEPS)
	$(CC) $(DEBUG) -c -o $@ $< $(CFLAGS)

chatserver: $(OBJ)
	$(CC) $(DEBUG) -Wall -pedantic -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -r chatserver $(OBJDIR)

$(shell mkdir -p $(OBJDIR))