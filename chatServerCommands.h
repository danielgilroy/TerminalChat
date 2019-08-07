#ifndef CHAT_SERVER_COMMANDS_H
#define CHAT_SERVER_COMMANDS_H

void whois_cmd(table_entry_t *, char *);
void whois_arg_cmd(table_entry_t *, int, int, char *, char *);
void who_cmd(int, char **);
void who_arg_cmd(int, char *, char *, char **);
void join_cmd(int, char *);
void join_arg_cmd(table_entry_t *, int, char *, char *, char **);
void nick_cmd(int, char *, char *);
void nick_arg_cmd(table_entry_t *, int, int, char *, char *, char **);
void where_cmd(int, int, char *);
void where_arg_cmd(int, int, char *, char *);
void kick_cmd(int, char *);
void kick_arg_cmd(table_entry_t *, table_entry_t *, int, int, char *, char *, char **);
void register_cmd(int, char *);
void register_arg_cmd(table_entry_t *, int, char *, char *);
void admin_cmd(int, char *);
void admin_arg_cmd(table_entry_t *, int, char *, char *);
bool die_cmd(table_entry_t *, char *);

#endif