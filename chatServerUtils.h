#ifndef CHAT_SERVER_UTILS_H
#define CHAT_SERVER_UTILS_H

int send_message(int, char *, int);
int send_message_to_all(int, char *, int);
char *add_username_to_message(char *, char *, char *);
void print_time();
int check_status(int, char *);
void get_username_and_passwords(int, char *, char **, char **, char **);
int is_password_valid(char *, char *);
int are_passwords_valid(char *, char *, char *);
int is_username_valid(char *, char *);
int is_username_restricted(char *, char *);
void rebuild_who_message(char **, int);
void remove_user(int, table_entry_t *);
void add_user(int, char *, size_t, bool, int, char *, unsigned short);
table_entry_t *get_user(int, char *);
void change_username(int, table_entry_t *, char *);
void delete_user(int, table_entry_t *);
int id_compare(table_entry_t *, table_entry_t *);
void secure_zero(volatile void *, size_t);

#endif