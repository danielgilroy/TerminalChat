CC = gcc
CFLAGS = -I.
DEBUG = -g -O0
DEPS = client.h client_tcp.h
OBJ = $(OBJDIR)/client.o $(OBJDIR)/client_tcp.o
LIBS = -lpthread -lncurses

VPATH = src
OBJDIR = obj

$(OBJDIR)/%.o: %.c $(DEPS)
	$(CC) $(DEBUG) -c -o $@ $< $(CFLAGS)

chatclient: $(OBJ)
	$(CC) $(DEBUG) -Wall -pedantic -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -r chatclient $(OBJDIR)

$(shell mkdir -p $(OBJDIR))