#ifndef CHAT_SERVER_COMMANDS_H
#define CHAT_SERVER_COMMANDS_H

#include "server_shared.h"
#include "server_utils.h"

void whois_cmd(int, table_entry_t *, char *);
void whois_arg_cmd(int, table_entry_t *, char *, char *);
void who_cmd(int, char **);
void who_arg_cmd(int, int, char *, char *, char **);
void join_cmd(int);
void join_arg_cmd(int, table_entry_t **, char *, char *, char **);
void nick_cmd(table_entry_t *, char *);
void nick_arg_cmd(int, table_entry_t **, char *, char *, char **);
void where_cmd(table_entry_t *, char *);
void where_arg_cmd(int, int, char *, char *);
void kick_cmd(int);
void kick_arg_cmd(int, table_entry_t *, table_entry_t **, char *, char *, char **);
void register_cmd(int);
void register_arg_cmd(int, table_entry_t *, char *, char *);
void unregister_cmd(int);
void unregister_arg_cmd(int, table_entry_t *, char *, char *);
void admin_cmd(int);
void admin_arg_cmd(int, table_entry_t *, char *, char *);
bool die_cmd(table_entry_t *);

#endif