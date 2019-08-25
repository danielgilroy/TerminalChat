#ifndef CHAT_SERVER_UTILS_H
#define CHAT_SERVER_UTILS_H

#include "server_shared.h"

#define RESTRICTED_STARTS {"client", "server"}
#define RESTRICTED_CONTAINS {"admin", "moderator"}

size_t prepare_client_message(char *, ssize_t);
char *add_username_to_message(const char *, const char *, const char *);
ssize_t send_message(int, const char *, size_t);
ssize_t send_message_to_all(int, const char *, size_t);
void get_username_and_passwords(int, char *, char **, char **, char **);
int get_admin_password(char *);
bool is_password_invalid(const char *, char *);
bool are_passwords_invalid(const char *, const char *, char *);
bool is_username_invalid(const char *, char *);
bool is_username_restricted(const char *, char *);
void rebuild_who_message(char **, int);
void remove_user(table_entry_t **);
table_entry_t *add_user(const char *, bool, int, size_t, int, char *, unsigned short);
table_entry_t *get_user(int, char *);
table_entry_t *find_user(const char *);
table_entry_t *change_username(table_entry_t **, char *);
void delete_user(table_entry_t **);
int id_compare(table_entry_t *, table_entry_t *);
int strncmp_case_insensitive(const char *, const char *, size_t);
bool string_contains(const char *, const char *);
void print_time();
int check_status(int, char *);
void secure_zero(volatile void *, size_t);

#endif