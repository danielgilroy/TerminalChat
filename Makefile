#Compilation flags
CC = gcc
CFLAGS = -I.
DEBUG = -g -O0

#Variables for charserver
SRCDIRS = chat_server/src
OBJDIRS = chat_server/obj
SRCS = $(SRCDIRS)/server.c $(SRCDIRS)/server_utils.c $(SRCDIRS)/server_commands.c
DEPS = $(SRCDIRS)/server.h $(SRCDIRS)/server_utils.h $(SRCDIRS)/server_commands.h $(SRCDIRS)/server_shared.h
OBJS = $(OBJDIRS)/server.o $(OBJDIRS)/server_utils.o $(OBJDIRS)/server_commands.o
LIBS = -lpthread -lsqlite3 -lsodium

#Variables for chatclient
SRCDIRC = chat_client/src
OBJDIRC = chat_client/obj
SRCC = $(SRCDIRC)/client.c $(SRCDIRC)/client_tcp.c
DEPC = $(SRCDIRC)/client.h $(SRCDIRC)/client_tcp.h
OBJC = $(OBJDIRC)/client.o $(OBJDIRC)/client_tcp.o
LIBC = -lpthread -lncurses

.PHONY: all
all: chatserver chatclient

#Build object for chatserver
$(OBJDIRS)/%.o: $(SRCDIRS)/%.c $(DEPS)
	$(CC) $(DEBUG) -c -o $@ $<

chatserver: $(OBJS)
	$(CC) $(DEBUG) -Wall -pedantic -o $@ $^ $(LIBS)

#Build object for chatclient
$(OBJDIRC)/%.o: $(SRCDIRC)/%.c $(DEPC)
	$(CC) $(DEBUG) -c -o $@ $<

chatclient: $(OBJC)
	$(CC) $(DEBUG) -Wall -pedantic -o $@ $^ $(LIBC)

.PHONY: clean
clean: 
	rm -r chatserver chatclient $(OBJDIRS) $(OBJDIRC)

#Create obj folders for client and server
$(shell mkdir -p $(OBJDIRS))
$(shell mkdir -p $(OBJDIRC))

