#include "chatServer.h"
#include "chatServerUtils.h"

int send_message(int socket, char *message, int message_length){

    int bytes_sent = 0;

    while(message_length){
        bytes_sent = send(socket, message, message_length, 0);
        if(bytes_sent == -1){
            fprintf(stderr, "Error sending message to socket %d: %s\n", socket, strerror(errno));
            return bytes_sent;
        }
        message += bytes_sent; //Point to the remaining portion that was not sent
        message_length -= bytes_sent; //Calculate the remaining bytes to be sent
    }

    return bytes_sent;
}

int send_message_to_all(int room_id, char *message, int message_length){

    //Prevent messages from being sent to everyone in the lobby room
    if(room_id == LOBBY_ROOM_ID){
        return -1;
    }

    int status = 0;
    table_entry_t *s;

    for(s = active_users[room_id]; s != NULL; s = s->hh.next) {
        status = send_message(s->socket_fd, message, message_length);                     
    }                                                            

    return status;
}

char *add_username_to_message(char *message, char *username, char *suffix){
//NOTE: Calling function must call free on the allocated memory

    size_t length = 1 + USERNAME_LENGTH + strlen(suffix) + MESSAGE_LENGTH + 1;
    char *message_result = malloc(length);
    if(message_result == NULL){
        fprintf(stderr, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    
    //Add a control character to start of message so we know when it's a new message
    message_result[0] = MESSAGE_START;
    message_result[1] = '\0';
    strncat(message_result, username, length);
    strncat(message_result, suffix, length);
    strncat(message_result, message, length);
    message_result[length - 1] = '\0'; //Ensure NULL termination
    return message_result;
}

void print_time(){
    time_t raw_time = time(NULL);
    struct tm *cur_time;

    //Get local time
    time(&raw_time);
    cur_time = localtime(&raw_time);  

    //Print time to terminal
    printf("%02d:%02d ", cur_time->tm_hour, cur_time->tm_min);  
}

int check_status(int status, char *error){
    if(status == -1){
        perror(error);
        exit(EXIT_FAILURE);
    }
    return status;
}

void get_username_and_passwords(int cmd_length, char *client_message, char **new_name, char **password, char **password2){
    
    //Skip over command in client's message
    *new_name = client_message + cmd_length;

    //Force the first letter to be uppercase
    (*new_name)[0] = toupper((*new_name)[0]);

    if(password == NULL){return;} //Calling function doesn't want password

    //Check if the user entered a password
    *password = memchr(*new_name, ' ', USERNAME_LENGTH);
    if(*password != NULL){

        //Null terminate username and get pointer to password
        (*password)[0] = '\0';
        (*password)++;

        if(password2 == NULL){return;} //Calling function doesn't want a second password

        //Check if the user entered a second password
        *password2 = memchr(*password, ' ', USERNAME_LENGTH);
        if(*password2 != NULL){

            //Null terminate previous password and get pointer to next password
            (*password2)[0] = '\0';
            (*password2)++;
        }
    }
}

int is_password_valid(char *password, char *error_message){

    //Check if password is too long
    if(!memchr(password, '\0', PASSWORD_LENGTH_MAX)){
        sprintf(error_message, "Server: Password is too long (max %d characters)", PASSWORD_LENGTH_MAX - 1);
        return 0;
    }
    //Check if password has any whitespace
    if(strpbrk(password, " \t\n\v\f\r")){
        sprintf(error_message, "Server: Passwords with spaces are restricted");
        return 0;                            
    }
    //Check if password is too short
    if(memchr(password, '\0', PASSWORD_LENGTH_MIN)){
        sprintf(error_message, "Server: Password is too short (min %d characters)", PASSWORD_LENGTH_MIN);
        return 0; 
    }

    return 1;
}

int are_passwords_valid(char *password, char *password2, char *error_message){

    //Check if password is valid
    if(!is_password_valid(password, error_message)){
        return 0;
    }
    //Check if password2 exists
    if(password2 == NULL){
        sprintf(error_message, "Server: The entered command requires the password be repeated");
        return 0;
    }
    //Check if password2 is valid
    if(!is_password_valid(password2, error_message)){
        return 0;
    }
    //Check is both passwords match
    if(strcmp(password, password2) != 0){
        sprintf(error_message, "Server: The two entered passwords do not match");
        return 0;
    }
    
    return 1;
}

int is_username_valid(char *username, char *error_message){

    //Check if username exists
    if(username == NULL){
        sprintf(error_message, "Server: The entered command requires a username");
        return 0;
    }
    //Check if username is too long
    if(!memchr(username, '\0', 16)){
        sprintf(error_message, "Server: Username is too long (max %d characters)", USERNAME_LENGTH - 1);
        return 0;
    }                   
    //Check if username has any whitespace
    if(strpbrk(username, " \t\n\v\f\r")){
        sprintf(error_message, "Server: Usernames with spaces are restricted");
        return 0;                            
    }
    //Check if username is blank
    if(strcmp(username, "") == 0){
        sprintf(error_message, "Server: Blank usernames are restricted");
        return 0;                              
    }

    return 1;
}

int is_username_restricted(char *username, char *error_message){
    
    char *restricted_contains[] = {"Admin", "Server", "Client", "Administrator", "Moderator"};
    char *restricted_exact[] = {"Empty"};

    //Allow restricted usernames that are registered in database and password protected
    if(strcasecmp(username, "Admin") == 0){
        return 1;
    }

    //Check if username contains a restricted keyword
    for(int i = 0; i < sizeof(restricted_contains) / sizeof(restricted_contains[0]); i++){
        if(strncasecmp(username, restricted_contains[i], strlen(restricted_contains[i])) == 0){
            sprintf(error_message, "Server: Usernames containing \"%s\" are restricted", restricted_contains[i]);
            return 0;  
        }
    }

    //Check if username is a restricted keyword
    for(int i = 0; i < sizeof(restricted_exact) / sizeof(restricted_exact[0]); i++){
        if(strcasecmp(username, restricted_exact[i]) == 0){
            sprintf(error_message, "Server: Username \"%s\" is restricted", username);
            return 0;  
        }
    }

    return 1;
}

void rebuild_who_message(char** who_message, int room_id){

    size_t who_message_length;

    //Check if the list of users needs to be rebuilt
    if(who_message[room_id][0] == '\0'){

        //Insert MESSAGE_START character
        who_message[room_id][0] = MESSAGE_START;
        //sprintf(who_message[room_id] + 1, "Server: Room #%d ", room_id);
        sprintf(who_message[room_id] + 1, "Room #%02d: ", room_id);
        
        //Check if chat room has users
        int room_user_count = HASH_COUNT(active_users[room_id]);
        if(room_user_count == 0){
            strncat(who_message[room_id], "Empty", WHO_MESSAGE_LENGTH);
        }else{

            //Get who_message string length - Add extra 1 for null character
            who_message_length = strlen(who_message[room_id]) + (room_user_count * USERNAME_LENGTH) + 1;

            //Allocate memory for the string if it's longer than initial allocated size
            if(who_message_length > WHO_MESSAGE_LENGTH){
                printf("realloc to %lu\n", who_message_length);
                char *new_ptr = realloc(who_message[room_id], who_message_length);
                if(new_ptr == NULL){
                    fprintf(stderr, "Error allocating memory for who_message\n");
                    exit(0);
                }
                who_message[room_id] = new_ptr;
            } 

            //Itterate through the hash table and append usernames
            table_entry_t *user;
            for(user = active_users[room_id]; user != NULL; user = user->hh.next) {
                strncat(who_message[room_id], user->id, WHO_MESSAGE_LENGTH);
                strncat(who_message[room_id], " ", WHO_MESSAGE_LENGTH);
            }
        }
    }
}

void remove_user(int room_id, table_entry_t *user){

    int i = user->index;
    
    //Clear spam timeout and message count so new users using the same spot aren't affected
    pthread_mutex_lock(&spam_lock);
    spam_timeout[i] = 0;
    spam_message_count[i] = 0;
    pthread_mutex_unlock(&spam_lock);

    //Close the client socket
    check_status(close(user->socket_fd), "Error closing client socket");

    //Set FD to ignore state, decrement socket count, and set who_message for rebuild
    socket_fds[i].fd = -1;
    socket_count--;

    //Remove user from active_user hash table
    delete_user(room_id, user);
}

void add_user(int room_id, char *username, size_t index, bool is_admin, int client_fd, char *ip, unsigned short port){
    
    table_entry_t *s;
    s = malloc(sizeof(table_entry_t));
    if(s == NULL){
        perror("Error allocating hash table memory for new user");
        exit(EXIT_FAILURE);
    }

    strncpy(s->id, username, USERNAME_LENGTH);
    s->index = index;
    s->is_admin = is_admin;
    s->socket_fd = client_fd;
    strncpy(s->ip, ip, INET_ADDRSTRLEN);
    s->port = port;

    HASH_ADD_STR(active_users[room_id], id, s);  //id: name of key field
    HASH_SRT(hh, active_users[room_id], id_compare); 
}

table_entry_t *get_user(int room_id, char *username){
    table_entry_t *user = NULL;
    HASH_FIND_STR(active_users[room_id], username, user);  //user: output pointer
    return user;
}

void change_username(int room_id, table_entry_t *user, char *username){
    add_user(room_id, username, user->index, user->is_admin, user->socket_fd, user->ip, user->port);
    delete_user(room_id, user);
}

void delete_user(int room_id, table_entry_t *user) {
    HASH_DEL(active_users[room_id], user);
    free(user);
}

int id_compare(table_entry_t *a, table_entry_t *b){
    return (strcasecmp(a->id, b->id));
}

//Function used to clear passwords from memory
void secure_zero(volatile void *s, size_t n){
    if(s == NULL){return;}
    volatile uint8_t *p = s; //Use volatile to prevent compiler optimization
    while(n > 0){
        *p = 0;
        p++;
        n--;
    }
}