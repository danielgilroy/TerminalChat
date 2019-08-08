CC = gcc
CFLAGS = -I.
DEBUG = -g -O0
DEPS = server.h server_utils.h server_commands.h server_shared.h
OBJ = $(OBJDIR)/server.o $(OBJDIR)/server_utils.o $(OBJDIR)/server_commands.o
LIBS = -lpthread -lsqlite3 -lsodium

VPATH = src
OBJDIR = obj

$(OBJDIR)/%.o: %.c $(DEPS)
	$(CC) $(DEBUG) -c -o $@ $< $(CFLAGS)

chatserver: $(OBJ)
	$(CC) $(DEBUG) -Wall -pedantic -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -r chatserver $(OBJDIR)

$(shell mkdir -p $(OBJDIR))