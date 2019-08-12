#ifndef CHAT_SERVER_UTILS_H
#define CHAT_SERVER_UTILS_H

#include "server_shared.h"

//char *prepare_client_message2(char *, int *);
int prepare_client_message(char *, int);
char *add_username_to_message(char *, char *, char *);
int send_message(int, char *, int);
int send_message_to_all(int, char *, int);
void print_time();
void get_username_and_passwords(int, char *, char **, char **, char **);
int is_password_invalid(char *, char *);
int are_passwords_invalid(char *, char *, char *);
int is_username_invalid(char *, char *);
int is_username_restricted(char *, char *);
void rebuild_who_message(char **, int);
void remove_user(table_entry_t **);
table_entry_t *add_user(char *, bool, int, size_t, int, char *, unsigned short);
table_entry_t *get_user(int, char *);
table_entry_t *find_user(char *);
table_entry_t *change_username(table_entry_t **, char *);
void delete_user(table_entry_t **);
int id_compare(table_entry_t *, table_entry_t *);
int check_status(int, char *);
void secure_zero(volatile void *, size_t);

#endif