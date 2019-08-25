#include "server_utils.h"

size_t prepare_client_message(char *client_message, ssize_t recv_status){

    //Replace ending \n with \0 or ending \r\n with \0\0 if they exist
    for(size_t i = 0; i < MESSAGE_SIZE; i++){
        if(client_message[i] == MESSAGE_END || client_message[i] == '\0'){
            return i + 1;
        }else if(client_message[i] == '\n'){
            client_message[i] = '\0';
            return i + 1;
        }else if(client_message[i] == '\r'){
            client_message[i] = '\0';
            client_message[i + 1] = '\0';
            return i + 2;
        }
    }
    
    //Nul terminate end of message if no ending characters were found 
    client_message[recv_status] = '\0';
    return (size_t) (recv_status + 1);
}

char *add_username_to_message(const char *message, const char *username, const char *suffix){
//NOTE: Calling function must call free on the allocated memory

    size_t length = 1 + USERNAME_SIZE + strlen(suffix) + MESSAGE_SIZE + 1;
    char *message_result = calloc(length, sizeof(char));
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

ssize_t send_message(int socket, const char *message, size_t message_length){

    ssize_t bytes_sent = 0;
    int tries = 24;

    while(message_length > 0){

        bytes_sent = send(socket, message, message_length, 0);

        if(bytes_sent == -1){
            if(bytes_sent == EWOULDBLOCK || bytes_sent == EAGAIN){
                //Wait for send buffer to have available space
                //This essentially replicates a blocking send so a time out is added 
                if(tries){
                    struct timespec wait_time = {0, 125000000L}; //0.125 seconds
                    nanosleep(&wait_time, NULL);
                    tries--;
                }else{
                    //Number of tries exceeded: 24 tries * 0.125 seconds = 3 seconds total wait
                    fprintf(stderr, "Sending message to socket %d has timed out\n", socket);
                    return bytes_sent;
                }      
            }else{
                fprintf(stderr, "Error sending message to socket %d: %s\n", socket, strerror(errno));
                return bytes_sent;
            }
        }else{
            message += bytes_sent; //Point to the remaining portion that was not sent
            message_length -= bytes_sent; //Calculate the remaining bytes to be sent
        }
    }

    return bytes_sent;
}

ssize_t send_message_to_all(int room_id, const char *message, size_t message_length){

    //Prevent messages from being sent to everyone in the lobby room
    if(room_id == LOBBY_ROOM_ID){
        return -1;
    }

    ssize_t status = 0;
    table_entry_t *s;

    for(s = active_users[room_id]; s != NULL; s = s->hh.next) {
        status = send_message(s->socket_fd, message, message_length);                     
    }                                                            

    return status;
}

void get_username_and_passwords(int cmd_length, char *client_message, char **new_name, char **password, char **password2){
    
    if(new_name == NULL){
        return;
    }

    //Skip over command in client's message
    *new_name = client_message + cmd_length;

    //Force the first letter to be uppercase
    (*new_name)[0] = toupper((*new_name)[0]);

    if(password == NULL){return;} //Calling function doesn't want password

    //Check if the user entered a password
    *password = memchr(*new_name, ' ', USERNAME_SIZE);
    if(*password != NULL){

        //Null terminate username and get pointer to password
        (*password)[0] = '\0';
        (*password)++;

        if(password2 == NULL){return;} //Calling function doesn't want a second password

        //Check if the user entered a second password
        *password2 = memchr(*password, ' ', PASSWORD_SIZE_MAX);
        if(*password2 != NULL){

            //Null terminate previous password and get pointer to next password
            (*password2)[0] = '\0';
            (*password2)++;
        }
    }else{
        if(password2 != NULL){ //Caller wants a second password but first password failed
            *password2 = NULL; //Ensure password2 doesn't point to garbage values
        }
    }
}

int get_admin_password(char *admin_password){

    int c = 0;
    int pos = 0;

    while((c = getchar()) != '\n'){
        if(pos > 0 && c == 0x7F){
             pos--;
        }else if(pos < PASSWORD_SIZE_MAX - 1 && c >= 0x20 && c <= 0x7E){
            admin_password[pos] = c;
            pos++;
        }
    }
    admin_password[pos] = '\0';
    
    return pos + 1; //Return size of string
}

bool is_password_invalid(const char *password, char *error_message){

    if(password == NULL){
        sprintf(error_message, SERVER_PREFIX "The command requires a password");
        return true;
    }

    //Check if too short
    if(memchr(password, '\0', PASSWORD_SIZE_MIN)){
        sprintf(error_message, SERVER_PREFIX "Password is too short (min %d characters)", PASSWORD_SIZE_MIN);
        return true; 
    }
    //Check if too long
    if(!memchr(password, '\0', PASSWORD_SIZE_MAX)){
        sprintf(error_message, SERVER_PREFIX "Password is too long (max %d characters)", PASSWORD_SIZE_MAX - 1);
        return true;
    }
    //Check if any whitespace
    if(strpbrk(password, " \t\n\v\f\r")){
        sprintf(error_message, SERVER_PREFIX "Passwords with spaces are restricted");
        return true;                            
    }

    return false;
}

bool are_passwords_invalid(const char *password1, const char *password2, char *error_message){

    //Check if password1 exists
    if(password1 == NULL){
        sprintf(error_message, SERVER_PREFIX "The command requires a password be entered twice");
        return true;
    }
    //Check if password1 is invalid
    if(is_password_invalid(password1, error_message)){
        return true;
    }
    //Check if password2 exists
    if(password2 == NULL){
        sprintf(error_message, SERVER_PREFIX "The command requires the password be repeated");
        return true;
    }
    //Check if password2 is invalid
    if(is_password_invalid(password2, error_message)){
        return true;
    }
    //Check is both passwords match
    if(strcmp(password1, password2) != 0){
        sprintf(error_message, SERVER_PREFIX "The two entered passwords do not match");
        return true;
    }
    
    return false;
}

bool is_username_invalid(const char *username, char *error_message){

    //Check if username exists
    if(username == NULL){
        sprintf(error_message, SERVER_PREFIX "The command requires a username");
        return true;
    }
    //Check if blank
    if(strcmp(username, "") == 0){
        sprintf(error_message, SERVER_PREFIX "Usernames cannot be blank");
        return true;                              
    }
    //Check if too long
    if(!memchr(username, '\0', USERNAME_SIZE)){
        sprintf(error_message, SERVER_PREFIX "Username is too long (max %d characters)", USERNAME_SIZE - 1);
        return true;
    }                   
    //Check if any whitespace
    if(strpbrk(username, " \t\n\v\f\r")){
        sprintf(error_message, SERVER_PREFIX "Usernames cannot have spaces");
        return true;                            
    }

    return false;
}

bool is_username_restricted(const char *username, char *error_message){
    
    char *restricted_starts[] = RESTRICTED_STARTS;
    char *restricted_contains[] = RESTRICTED_CONTAINS;
    char *restricted_word = NULL;

    //Check if username starts with a restricted keyword
    for(int i = 0; i < sizeof(restricted_starts) / sizeof(restricted_starts[0]); i++){
        restricted_word = restricted_starts[i];
        if(strncmp_case_insensitive(username, restricted_starts[i], strlen(restricted_word)) == 0){
            sprintf(error_message, SERVER_PREFIX "Usernames starting with \"%s\" are restricted", restricted_word);
            return true;  
        }
    }

    //Check if username contains a restricted keyword
    for(int i = 0; i < sizeof(restricted_contains) / sizeof(restricted_contains[0]); i++){
        restricted_word = restricted_contains[i];
        if(string_contains(username, restricted_word)){
            sprintf(error_message, SERVER_PREFIX "Usernames containing \"%s\" are restricted", restricted_word);
            return true;  
        }
    }

    return false;
}

void rebuild_who_message(char **who_messages, int room_id){

    size_t who_message_size;
    static size_t allocated_lengths[MAX_ROOMS];

    if(who_messages == NULL){
        fprintf(stderr, "Error in rebuild_who_message(): who_messages is NULL\n"); 
        return;
    }

    //Perform initial allocation of memory if needed
    if(who_messages[room_id] == NULL){
        who_messages[room_id] = malloc(WHO_MESSAGE_SIZE * sizeof(**who_messages));
        if(who_messages[room_id] == NULL){
            fprintf(stderr, "Error allocating memory for room #%d who_message\n", room_id);
            exit(EXIT_FAILURE);
        }
        allocated_lengths[room_id] = WHO_MESSAGE_SIZE;
        who_messages[room_id][0] = '\0'; //Set who_message to rebuild state
    }

    //Check if the list of users needs to be rebuilt
    if(who_messages[room_id][0] == '\0'){

        //Insert MESSAGE_START character
        who_messages[room_id][0] = MESSAGE_START;
        sprintf(who_messages[room_id] + 1, "Room #%02d: ", room_id);
        
        //Check if chat room has users
        int room_user_count = HASH_COUNT(active_users[room_id]);
        if(room_user_count > 0){

            //Get who_message string length - Add extra 1 for null character
            who_message_size = strlen(who_messages[room_id]) + (room_user_count * USERNAME_SIZE) + 1;

            //Allocate memory for the string if it's longer than initial allocated size
            if(who_message_size > allocated_lengths[room_id]){
                char *new_ptr = realloc(who_messages[room_id], who_message_size * sizeof(**who_messages));
                if(new_ptr == NULL){
                    fprintf(stderr, "Error allocating memory for who_message\n");
                    exit(0);
                }
                who_messages[room_id] = new_ptr;
                allocated_lengths[room_id] = who_message_size;
            } 

            //Itterate through the hash table and append usernames
            table_entry_t *user;
            for(user = active_users[room_id]; user != NULL; user = user->hh.next) {
                strncat(who_messages[room_id], user->id, who_message_size);
                strncat(who_messages[room_id], " ", who_message_size);
            }
        }
    }
}

void remove_user(table_entry_t **user){

    int i = (*user)->index;
    
    //Clear spam timeout and message count so new users using the same spot aren't affected
    pthread_mutex_lock(&spam_lock);
    spam_message_count[i] = 0;
    spam_timeout[i] = 0;
    pthread_mutex_unlock(&spam_lock);

    //Close the client socket
    check_status(close((*user)->socket_fd), "Error closing client socket");

    //Set FD to ignore state, decrement socket count, and set who_message for rebuild
    socket_fds[i].fd = -1;
    socket_count--;

    //Remove user from active_user hash table
    delete_user(user);
}

table_entry_t * add_user(const char *username, bool is_admin, int room_id, size_t index, int client_fd, char *ip, unsigned short port){
    
    table_entry_t *new_user;
    new_user = malloc(sizeof(table_entry_t));
    if(new_user == NULL){
        perror("Error allocating hash table memory for new user");
        exit(EXIT_FAILURE);
    }

    strncpy(new_user->id, username, USERNAME_SIZE);
    new_user->is_admin = is_admin;
    new_user->room_id = room_id;
    new_user->index = index;
    new_user->socket_fd = client_fd;
    strncpy(new_user->ip, ip, INET_ADDRSTRLEN);
    new_user->port = port;
    new_user->message = NULL;
    new_user->message_size = 1; //Set to 1 for empty string size "\0"

    HASH_ADD_STR(active_users[room_id], id, new_user);  //id: name of key field
    HASH_SRT(hh, active_users[room_id], id_compare); 

    return new_user;
}

table_entry_t *get_user(int room_id, char *username){
    table_entry_t *user = NULL;
    HASH_FIND_STR(active_users[room_id], username, user);  //user: output pointer
    return user;
}

table_entry_t *find_user(const char *username){
    table_entry_t *user = NULL;
    for(int room_index = 0; room_index < MAX_ROOMS; room_index++){
        HASH_FIND_STR(active_users[room_index], username, user);  //user: output pointer
        if(user != NULL){
            return user;
        }
    }
    return NULL;
}

table_entry_t * change_username(table_entry_t **user, char *username){
    table_entry_t *tmp = NULL;
    tmp = add_user(username, (*user)->is_admin, (*user)->room_id, (*user)->index, (*user)->socket_fd, (*user)->ip, (*user)->port);
    delete_user(user);
    *user = tmp;
    return *user;
}

void delete_user(table_entry_t **user) {
    int room_id = (*user)->room_id;
    HASH_DEL(active_users[room_id], *user);
    free(*user);
    *user = NULL;
}

int id_compare(table_entry_t *a, table_entry_t *b){
    return (strncmp_case_insensitive(a->id, b->id, USERNAME_SIZE));
}

int strncmp_case_insensitive(const char *a, const char *b, size_t n){
  int a_char, b_char;
  do{
     a_char = (unsigned char) *a++;
     b_char = (unsigned char) *b++;
     a_char = tolower(toupper(a_char)); //Round-trip conversion for issues where the uppercase char 
     b_char = tolower(toupper(b_char)); //does not have a 1-to-1 mapping with lowercase ones
     n--;
   }while(a_char == b_char && a_char != '\0' && n > 0);
   return a_char - b_char;
}

bool string_contains(const char *string, const char *substring){

    const char *substring_ptr = substring;
    int c = 0;

    do{
        c = (unsigned char) *string;
        if(tolower(toupper(c)) == *substring_ptr){
            substring_ptr++;
        }else if(substring_ptr != substring){
            //Reset substring_ptr and test current string character again
            substring_ptr = substring;
            continue;
        }
        string++;
    }while(*string != '\0' && *substring_ptr != '\0');

    if(*substring_ptr == '\0'){
        return true;
    }
    
    return false;
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
    }
    return status;
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