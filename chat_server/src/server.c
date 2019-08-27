#include "server.h"
#include <termios.h>

/* Extern Definitions */
int socket_count = 0;
struct pollfd socket_fds[MAX_SOCKETS];
table_entry_t *active_users[MAX_ROOMS] = {NULL}; 

short spam_message_count[MAX_SOCKETS]; //Spam message counters for each client
short spam_timeout[MAX_SOCKETS]; //Spam timeout for each client
pthread_mutex_t spam_lock;

sqlite3 *user_db;
/* ----------------- */

pthread_attr_t spam_tattr;
pthread_t spam_tid;
bool shutdown_server_flag = false;
unsigned int port_number = DEFAULT_PORT_NUMBER;

int main(int argc, char* argv[]){

    //Setup signal handlers to properly close server
    signal(SIGINT, terminate_server); //CTRL + C
    signal(SIGQUIT, terminate_server); //CTRL + BACKSLASH
    signal(SIGSEGV, terminate_server); //Memory access violation

    //Get port number from argument
    if(argc > 1){
        port_number = atoi(argv[1]);
    }

    //Turn off input echoing
    struct termios oldtc, newtc;
    tcgetattr(STDIN_FILENO, &oldtc);
    newtc = oldtc;
    newtc.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newtc);

    pthread_mutex_init(&spam_lock, NULL);
    
    printf("**Opening Database**\n");
    open_database();
    printf("**Starting Server**\n");
    start_server();

    printf("**Shutting Down Server**\n");

    //Turn echoing back on
    tcsetattr(STDIN_FILENO, TCSANOW, &oldtc);
    
    pthread_mutex_destroy(&spam_lock);

    return 0;
}

void open_database(){

    int status;
    const char *query;
    sqlite3_stmt *stmt;

    //Open database of registered users or create one if it doesn't already exist
    if(sqlite3_open("users.db", &user_db) != SQLITE_OK){
        fprintf(stderr, "Error opening database: %s\n", sqlite3_errmsg(user_db));
        sqlite3_close(user_db);
    }

    //Create "users" table if it doesn't already exist  
    query = "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY NOT NULL, password TEXT NOT NULL, type TEXT NOT NULL);";
    sqlite3_prepare_v2(user_db, query, -1, &stmt, NULL);
    if(sqlite3_step(stmt) != SQLITE_DONE){
        fprintf(stderr, "SQL error while creating table: %s\n", sqlite3_errmsg(user_db));
        exit(EXIT_FAILURE);
    }
    sqlite3_finalize(stmt);

    //Check if initial admin account has already been created
    query = "SELECT 1 FROM users WHERE type = 'admin';";
    sqlite3_prepare_v2(user_db, query, -1, &stmt, NULL);
    if((status = sqlite3_step(stmt)) == SQLITE_ROW){
       sqlite3_finalize(stmt);
       return; //Initial admin account already exists
    }else if(status != SQLITE_DONE){
        fprintf(stderr, "SQL error while checking for admin: %s\n", sqlite3_errmsg(user_db));
        exit(EXIT_FAILURE);
    }
    sqlite3_finalize(stmt);

    //Create initial admin account
    create_admin();
}

void create_admin(){

    char admin_password[MESSAGE_SIZE];
    char admin_password2[MESSAGE_SIZE];
    char hashed_password[crypto_pwhash_STRBYTES];
    char password_error[MESSAGE_SIZE];
    char *matching_error = NULL;

    const char *query;
    sqlite3_stmt *stmt;

    printf("**Creating Admin Account**\n");

    //Get admin password from server administrator
    do{

        //Reset password_error for new iteration
        password_error[0] = '\0';

        //Print error message from previous iteration
        if(matching_error){
            printf("%s\n\n", matching_error);
        }

        do{
            if(*password_error){ //Print error message if not blank
                printf("%s\n\n", password_error + strlen(SERVER_PREFIX)); //Skip over SERVER_PREFIX
            }

            printf("Enter password for \"Admin\" account: ");
            get_admin_password(admin_password);
            printf("\n");

        }while(is_password_invalid(admin_password, password_error));

        printf("Retype the same password: ");
        get_admin_password(admin_password2);
        printf("\n");

        //Set matching_error message for next loop iteration
        matching_error = "The entered passwords do not match";
        
    }while(strncmp(admin_password, admin_password2, PASSWORD_SIZE_MAX) != 0);

    //Hash password with libsodium
    if(crypto_pwhash_str(hashed_password, admin_password, strlen(admin_password), 
        PWHASH_OPSLIMIT, PWHASH_MEMLIMIT) != 0){
        /* out of memory */
        fprintf(stderr, "Ran out of memory during hash function\n");
        exit(EXIT_FAILURE);
    }

    //Clear the plain-text passwords from memory
    secure_zero(admin_password, PASSWORD_SIZE_MAX);
    secure_zero(admin_password2, PASSWORD_SIZE_MAX);

    //Register admin account into database with specified password
    query = "INSERT INTO users(id, password, type) VALUES('Admin', ?1, 'admin');";
    sqlite3_prepare_v2(user_db, query, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, hashed_password, -1, SQLITE_STATIC);
    if(sqlite3_step(stmt) != SQLITE_DONE){
        fprintf(stderr, "SQL error while inserting admin account: %s\n", sqlite3_errmsg(user_db));
        exit(EXIT_FAILURE);
    }else{
        printf("**Admin Account Created**\n");
    }
    sqlite3_finalize(stmt);
}

void start_server(){

    int status;
    int flags;
    
    //Define the server's IP address and port
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port_number);
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    memset(server_address.sin_zero, 0, sizeof(server_address.sin_zero));

    //Create the server socket to use for a connection
    int server_socket;
    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    check_status(server_socket, "Error creating server socket");

    //Set server socket to nonblocking
    flags = fcntl(server_socket, F_GETFL, NULL);
    check_status(flags, "Error getting flags for server socket");
    status = fcntl(server_socket, F_SETFL, flags | O_NONBLOCK);
    check_status(status, "Error setting server socket to nonblocking");

    //Bind the socket to our specified IP address and port
    status = bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));
    if(check_status(status, "\nError binding server socket")){
        fprintf(stderr, "Server will select an unused port instead of port %d\n", port_number);
        server_address.sin_port = 0; //Set port to automatically find an unused port
        status = bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));
        check_status(status, "Error binding server socket");
    }

    //Print the server port to the terminal
    socklen_t len = sizeof(server_address);
    if(getsockname(server_socket, (struct sockaddr *)&server_address, &len) == -1){
        perror("getsockname error");
        return;
    }    
    port_number = ntohs(server_address.sin_port);
    printf("Server is using port number: %d\n", port_number);

    //Set the socket up to listen for connections
    status = listen(server_socket, LISTEN_BACKLOG);
    check_status(status, "Error listening on server socket");

    //Initialize struct pollfd array to zeros
    memset(socket_fds, 0, sizeof(socket_fds));

    //Set server file descriptor and event type
    socket_fds[0].fd = server_socket;
    socket_fds[0].events = POLLIN;
    socket_count++;

    //Set ignore state for client file descriptors and event type
    for(size_t i = 1; i < MAX_SOCKETS; i++){
        socket_fds[i].fd = -1;
        socket_fds[i].events = POLLIN;
    }
    
    //Create thread for spam timer in a detached state
    if(pthread_attr_init(&spam_tattr)){
        perror("Error initializing pthread attribute");
        exit(EXIT_FAILURE);
    }
    if(pthread_attr_setdetachstate(&spam_tattr, PTHREAD_CREATE_DETACHED)){
        perror("Error setting pthread detach state");
        exit(EXIT_FAILURE);
    }
    if(pthread_create(&spam_tid, &spam_tattr, spam_timer, NULL)){
        perror("Error creating pthread");
        exit(EXIT_FAILURE);
    }
    if(pthread_attr_destroy(&spam_tattr)){
        perror("Error destroying pthread attribute");
        exit(EXIT_FAILURE);
    }

    //Call method for processing clients
    monitor_connections(server_socket);

    //Close the server socket
    check_status(close(server_socket), "Error closing server socket");

    //Close database of registered users
    status = sqlite3_close(user_db);
    if(status != SQLITE_OK){
        fprintf(stderr, "Error closing database: %s\n", sqlite3_errmsg(user_db));
    }
}

void *spam_timer(){

    int current_interval = 0; //Current interval within spam interval window

    while(1){

        //Each interval is one second long
        sleep(1);
        current_interval++;

        //Reset spam message counters to be used in new spam interval window
        if(current_interval % SPAM_INTERVAL_WINDOW == 0){
            pthread_mutex_lock(&spam_lock);
            memset(spam_message_count, 0, sizeof(spam_message_count));
            pthread_mutex_unlock(&spam_lock);
            current_interval = 0;
        }

        //Reduce every client's timeout period by one second until it's zero
        pthread_mutex_lock(&spam_lock);
        for(size_t i = 1; i < MAX_SOCKETS; i++){
            if(spam_timeout[i] > 0){
                spam_timeout[i]--;
            }
        }
        pthread_mutex_unlock(&spam_lock);
    }
}

void monitor_connections(int server_socket){

    int status;
    char server_msg_prefixed[MESSAGE_SIZE + 1];
    char *server_msg = server_msg_prefixed + 1;
    char *who_messages[MAX_ROOMS] = {NULL};

    //Add control character to the start of message so we know when it's a
    //new message since the message may be split up over multiple packets
    server_msg_prefixed[0] = MESSAGE_START;

    //Perform initial allocation/build of who_messages
    for(int room_id = 0; room_id < MAX_ROOMS; room_id++){
        rebuild_who_message(who_messages, room_id);
    }

    printf("**Awaiting Clients**\n");
        
    while(1){
        
        //Monitor FDs for any activated events
        status = poll(socket_fds, MAX_SOCKETS, -1);

        //Check if a poll error has occurred
        if(status == -1){
            perror("Poll Error");
            continue;
        }
    
        /* ------------------------------------------ */
        /* Event has occurred: Check server socket */
        /* ------------------------------------------ */
        if(socket_fds[0].revents & POLLIN){
            accept_clients(server_socket, server_msg_prefixed, who_messages);
        }
        
        /* ----------------------------------------------------------------- */
        /* Event has occurred: Check all active clients in every chat room */
        /* ----------------------------------------------------------------- */
        process_clients(server_msg_prefixed, who_messages);

        //Check if server has been flagged for shutdown
        if(shutdown_server_flag){
            break;
        }
    }
    
    /* --------------- */
    /* Shutdown server */
    /* --------------- */
    shutdown_server(who_messages);
}

void accept_clients(int server_socket, char *server_msg_prefixed, char **who_messages){
    
    int status, flags;
    int client_socket;
    static size_t index = 0;
    char username[USERNAME_SIZE];
    char *server_msg = server_msg_prefixed + 1;
    const char *server_msg_literal = NULL;

    struct sockaddr_in client_addr;
    socklen_t client_addr_size = sizeof(client_addr);
    char ip_str[INET_ADDRSTRLEN];
    unsigned short port;
        
    while(1){
    
        //Check for any pending connections
        client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &client_addr_size);

        //Accept all pending connections until queue is empty or an error occurs
        if(client_socket == -1){
            if(errno != EWOULDBLOCK && errno != EAGAIN){
                perror("Error accepting new client");
            }else{
                //No more pending connections
            }

            return;
        }

        //Check if server is full
        if(socket_count >= MAX_SOCKETS){
            printf("**Server has reached the maximum of %d clients**\n", MAX_SOCKETS - 1);
            sprintf(server_msg, SERVER_PREFIX "The server has reached the maximum of %d clients", MAX_SOCKETS - 1);
            send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
            status = close(client_socket);
            check_status(status, "Error closing client socket");
            continue;
        }

        //Increment socket count and set lobby who_messages for rebuild
        socket_count++;
        who_messages[LOBBY_ROOM_ID][0] = '\0';
        
        //Set client socket to nonblocking
        flags = fcntl(client_socket, F_GETFL, NULL);
        check_status(flags, "Error getting flags for client socket");
        status = fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
        check_status(status, "Error setting client socket to nonblocking");
        
        //Get the ip address and port number of the connecting user
        inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, sizeof(ip_str));
        port = ntohs(client_addr.sin_port);

        //Find an available spot in the client FD array
        while(socket_fds[index].fd > 0){
            index = (index + 1) % MAX_SOCKETS;
        }

        //Assign the socket to the client FD
        socket_fds[index].fd = client_socket;

        //Create client's default username
        sprintf(username, "Client%zu", index);

        //Add client to the lobby room in active_users hash table
        add_user(username, false, LOBBY_ROOM_ID, index, client_socket, ip_str, port);

        //Send server welcome messages to client
        sprintf(server_msg, SERVER_PREFIX "Welcome to the server - Default username is \"%s\"", username);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        server_msg_literal = MESSAGE_START_STR SERVER_PREFIX "Use the /nick command to change your username";
        send_message(client_socket, server_msg_literal, strlen(server_msg_literal) + 1);
        server_msg_literal = MESSAGE_START_STR SERVER_PREFIX "Use the /join command to join a chat room";
        send_message(client_socket, server_msg_literal, strlen(server_msg_literal) + 1); 
        
        //Print client joining message to the server's terminal
        printf("**Client%lu on socket %d (%s:%hu) joined the server**\n", index, client_socket, ip_str, port);
    }
}

void process_clients(char *server_msg_prefixed, char **who_messages){

    ssize_t recv_status = 0; 
    size_t msg_size = 0;
    size_t index = 0;
    int client_socket = 0;
    int cmd_length = 0;
    bool expect_ending_char = false;
    char *server_msg = server_msg_prefixed + 1;
    const char *server_msg_literal = NULL;
    static bool message_recv[MAX_SOCKETS];
    static char client_msg[MESSAGE_SIZE + 1];
    static char packet_msg[MESSAGE_SIZE + 1];

    //Fail-safe to ensure NUL terminated client message
    client_msg[MESSAGE_SIZE] = '\0';
    packet_msg[MESSAGE_SIZE] = '\0';
    char *packet_ptr = packet_msg;

    memset(message_recv, false, sizeof(message_recv));

    //Iterate through every chat room
    for(int room_index = 0; room_index < MAX_ROOMS; room_index++){

        //Iterate through all users in the chat room
        table_entry_t *user, *tmp;
        HASH_ITER(hh, active_users[room_index], user, tmp){ //Uthash deletion-safe iteration

            //Get index and socket from user entry
            index = user->index;
            client_socket = user->socket_fd;

            //Check if user has already been processed
            if(message_recv[index]){
                continue;
            }

            //Continue if no active event for FD
            if(!(socket_fds[index].revents & POLLIN)){  
                continue;
            }              

            //Receive messages from client sockets with active events
            recv_status = recv(client_socket, packet_msg, MESSAGE_SIZE, 0);
            if(recv_status == -1){
                if(errno != EWOULDBLOCK && errno != EAGAIN){
                    perror("Error receiving message from client socket");
                }
                continue;
            }
            
            //Check if client has left the server
            if(recv_status == 0){
                remove_client(user, server_msg_prefixed, who_messages);
                continue;
            }
            
            //Mark socket as messaged received 
            message_recv[index] = true;

            //Point to first message in packet and reset flag
            packet_ptr = packet_msg;
            expect_ending_char = false;

            while(recv_status > 0){

                //Copy packet message to client message
                if(packet_ptr[0] == MESSAGE_START){
                    //Skip over message-start control character
                    packet_ptr++;
                    recv_status--;
                    //Copy the new message
                    strncpy(client_msg, packet_ptr, recv_status);
                    client_msg[recv_status] = '\0';
                    expect_ending_char = true;
                }else if(user->message){
                    //Copy the old incomplete message
                    strncpy(client_msg, user->message, user->message_size);
                    //Concatenate the new message
                    strncat(client_msg, packet_ptr, recv_status);
                    expect_ending_char = true;
                }else{
                    //Handle message normally
                    strncpy(client_msg, packet_ptr, recv_status);
                    expect_ending_char = false;
                }

                //Prepare client message for processing
                msg_size = prepare_client_message(client_msg, &recv_status);

                //Check if message is completed or not
                if(client_msg[msg_size - 1] == MESSAGE_END){
                    //Change MESSAGE_END ending to "\0" and process message
                    client_msg[msg_size - 1] = '\0';
                    //Reset flag for next message
                    expect_ending_char = false;
                }else if(expect_ending_char){ 
                    
                    //Store incomplete message for later processing
                    char *incomplete_msg = user->message;
                    if(incomplete_msg == NULL){
                        incomplete_msg = malloc(MESSAGE_SIZE * sizeof (*incomplete_msg));
                        if(incomplete_msg == NULL){
                            perror("Error allocating incomplete message for user");
                            exit(EXIT_FAILURE);
                        }
                    }

                    //Copy incomplete message to user's message buffer
                    strncpy(incomplete_msg, client_msg, msg_size);
                    user->message = incomplete_msg;
                    user->message_size = msg_size;

                    //Adjust recv_status to remaining bytes and point to next message
                    if(msg_size > 1){
                        recv_status -= (ssize_t) (msg_size - 1);
                        packet_ptr += (msg_size - 1);
                    }else{
                        //Subtract 1 if there is only a single control character remaining
                        //Fail safe to prevent infinite loop on bad input
                        recv_status -= 1;
                        packet_ptr += 1;
                    }

                    continue;
                }

                if(client_msg[0] == '\0'){
                    /* ----------------------------- */
                    /* Ignore client's empty message */
                    /* ----------------------------- */
                }else if(client_msg[0] == '/'){
                    /* ------------------------------- */
                    /* Process client's server command */
                    /* ------------------------------- */

                    if(strcmp(client_msg, "/whois") == 0){
                        //Return the client's IP address and port
                        cmd_length = 6;
                        whois_cmd(cmd_length, user, client_msg);

                    } //Fallthrough to targeted /whois command

                    if(strncmp(client_msg, "/whois ", cmd_length = 7) == 0){
                        //Return the targeted user's IP address and port
                        whois_arg_cmd(cmd_length, user, client_msg, server_msg_prefixed);

                    }else if(strcmp(client_msg, "/who") == 0){
                        //List who's in every chat room
                        who_cmd(client_socket, who_messages);

                    }else if(strncmp(client_msg, "/who ", cmd_length = 5) == 0){
                        //List who's in the specified chat room
                        who_arg_cmd(cmd_length, client_socket, client_msg, server_msg_prefixed, who_messages);

                    }else if(strcmp(client_msg, "/join") == 0){
                        //Inform client of /join usage
                        join_cmd(client_socket);

                    }else if(strncmp(client_msg, "/join ", cmd_length = 6) == 0){
                        //Join the user-specified chat room
                        join_arg_cmd(cmd_length, &user, client_msg, server_msg_prefixed, who_messages);

                    }else if(strcmp(client_msg, "/nick") == 0){
                        //Echo back the client's username
                        nick_cmd(user, server_msg_prefixed);
                        
                    }else if(strncmp(client_msg, "/nick ", cmd_length = 6) == 0){
                        //Change the client's username
                        nick_arg_cmd(cmd_length, &user, client_msg, server_msg_prefixed, who_messages);
                        //Clear passwords from every buffer
                        secure_zero(packet_msg, msg_size);
                        secure_zero(client_msg, msg_size);
                        secure_zero(user->message, msg_size);

                    }else if(strcmp(client_msg, "/where") == 0){
                        //Return the chat room you are currently in
                        where_cmd(user, server_msg_prefixed);

                    }else if(strncmp(client_msg, "/where ", cmd_length = 7) == 0){
                        //Return the room number that has the specified-user
                        where_arg_cmd(cmd_length, client_socket, client_msg, server_msg_prefixed);
                    
                    }else if(strcmp(client_msg, "/kick") == 0){
                        //Inform client of /kick usage
                        kick_cmd(client_socket);

                    }else if(strncmp(client_msg, "/kick ", cmd_length = 6) == 0){
                        //Kick specified user from the server
                        kick_arg_cmd(cmd_length, user, &tmp, client_msg, server_msg_prefixed, who_messages);

                    }else if(strcmp(client_msg, "/register") == 0){
                        //Inform client of /register usage
                        register_cmd(client_socket);
                        
                    }else if(strncmp(client_msg, "/register ", cmd_length = 10) == 0){
                        //Register username in user database
                        register_arg_cmd(cmd_length, user, client_msg, server_msg_prefixed);
                        //Clear passwords from every buffer
                        secure_zero(packet_msg, msg_size);
                        secure_zero(client_msg, msg_size);
                        secure_zero(user->message, msg_size);

                    }else if(strcmp(client_msg, "/unregister") == 0){
                        //Inform client of /unregister usage
                        unregister_cmd(client_socket);
                        
                    }else if(strncmp(client_msg, "/unregister ", cmd_length = 12) == 0){
                        //Unregister username from user database
                        unregister_arg_cmd(cmd_length, user, client_msg, server_msg_prefixed);
                        //Clear passwords from every buffer
                        secure_zero(packet_msg, msg_size);
                        secure_zero(client_msg, msg_size);
                        secure_zero(user->message, msg_size);

                    }else if(strcmp(client_msg, "/admin") == 0){
                        //Inform client of /admin usage
                        admin_cmd(client_socket);

                    }else if(strncmp(client_msg, "/admin ", cmd_length = 7) == 0){
                        //Change account type of targeted user
                        admin_arg_cmd(cmd_length, user, client_msg, server_msg_prefixed);

                    }else if(strcmp(client_msg, "/die") == 0){
                        //Trigger server shutdown if admin
                        if(die_cmd(user)){
                            shutdown_server_flag = true;
                            break;
                        }
                    
                    }else{
                        //Remove arguments after the command if they exist
                        char *arguments = memchr(client_msg, ' ', msg_size);
                        if(arguments){
                            arguments[0] = '\0';
                        }
                        //Inform client of invalid command
                        sprintf(server_msg, SERVER_PREFIX "\"%s\" is not a valid command", client_msg);
                        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
                    }
                    
                }else{
                    /* --------------------- */
                    /* Send client's message */
                    /* --------------------- */

                    //Check for and handle spamming clients
                    if(check_for_spamming(user, server_msg_prefixed)){
                        //User has spam timeout
                        break;
                    }else{
                        //Increment spam message count for client
                        pthread_mutex_lock(&spam_lock);
                        spam_message_count[index]++;
                        pthread_mutex_unlock(&spam_lock);
                    }
                    
                    if(client_msg[0] == '@'){
                        /* ------------------------------------- */
                        /* Send private message to targeted user */
                        /* ------------------------------------- */
                        private_message(user, client_msg, msg_size, server_msg_prefixed);
                    }else if(user->room_id == LOBBY_ROOM_ID){
                        //Inform client they aren't in a chat room
                        server_msg_literal = MESSAGE_START_STR SERVER_PREFIX "You're not in a chat room - Use the /join command";
                        send_message(client_socket, server_msg_literal, strlen(server_msg_literal) + 1);
                    }else{
                        /* -------------------------------- */
                        /* Send public message to chat room */
                        /* -------------------------------- */            
                        public_message(user, client_msg, msg_size);
                    }
                }

                //Adjust recv_status to remaining bytes not yet processed
                recv_status -= (ssize_t) (msg_size - (user->message_size - 1));

                //Point to next message in the packet
                packet_ptr += (msg_size - (user->message_size - 1));
                                    
                //Reset user's message buffer
                if(user->message){
                    free(user->message);
                    user->message = NULL;
                    user->message_size = 1; //Set to 1 for empty string size "\0"
                }
            }
        }
    }
}

int check_for_spamming(table_entry_t *user, char *server_msg_prefixed){

    int index = user->index;
    int client_socket = user->socket_fd;
    char *server_msg = server_msg_prefixed + 1;

    pthread_mutex_lock(&spam_lock);
    if(spam_timeout[index] != 0){ 
        //Client currently has a timeout period
        sprintf(server_msg, "Spam Timeout: Please wait %d seconds", spam_timeout[index]);
        pthread_mutex_unlock(&spam_lock);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return 1;
    }else if(spam_message_count[index] > SPAM_MESSAGE_LIMIT){ 
        //Give client a timeout period
        spam_timeout[index] = SPAM_TIMEOUT_LENGTH;
        pthread_mutex_unlock(&spam_lock);
        sprintf(server_msg, "Spam Timeout: Please wait %d seconds", SPAM_TIMEOUT_LENGTH);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return 1;
    }
    pthread_mutex_unlock(&spam_lock);

    return 0;
}

void private_message(table_entry_t *user, char *client_msg, size_t msg_size, char *server_msg_prefixed){

    int client_socket = user->socket_fd;
    char *server_msg = server_msg_prefixed + 1;
    char target_username[USERNAME_SIZE];
    size_t target_username_length = strcspn(client_msg + 1, " ");

    //Check if targeted username is too long
    if(target_username_length > USERNAME_SIZE - 1){
        sprintf(server_msg, SERVER_PREFIX "Username is too long (max %d characters)", USERNAME_SIZE - 1);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Copy targeted username from client's message
    strncpy(target_username, client_msg + 1, target_username_length);
    target_username[target_username_length] = '\0'; //NUL terminate username
    target_username[0] = toupper(target_username[0]); //Capitalize username

    //Look for user in all chat rooms
    table_entry_t *target_user = find_user(target_username);

    //Inform client if user was not found
    if(target_user == NULL){
        sprintf(server_msg, SERVER_PREFIX "The user \"%s\" does not exist", target_username);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Remove '@' character, username, and empty space from client's message
    char *message = client_msg + 1 + target_username_length + 1;
    msg_size -= (1 + target_username_length + 1);

    //Check if message to user is blank
    if(message[0] == '\0' || message[-1] != ' '){
        sprintf(server_msg, SERVER_PREFIX "The message to \"%s\" was blank", target_username);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Add sender's username to message
    char *username = user->id;
    char *postfix = PRIVATE_PREFIX;
    message = add_username_to_message(message, username, postfix);
    size_t additional_length = strlen(username) + strlen(postfix) + 1; //Add one for MESSAGE_START

    //Send message to target user and sender
    send_message(target_user->socket_fd, message, msg_size + additional_length);
    if(target_user->socket_fd != client_socket){
        send_message(client_socket, message, msg_size + additional_length);
    }

    free(message);
    message = NULL;
}

void public_message(table_entry_t *user, char *client_msg, size_t msg_size){

    int room_id = user->room_id;
    char *username = user->id;

    //Add sender's username to message
    char *postfix = PUBLIC_PREFIX;
    char *message = add_username_to_message(client_msg, username, postfix);      
    size_t additional_length = strlen(username) + strlen(postfix) + 1; //Add one for MESSAGE_START       

    //Send message to all clients
    send_message_to_all(room_id, message, msg_size + additional_length);

    //Print client's message to server console
    print_time();
    printf("#%d ", room_id);
    printf("%s\n", message + 1); //Add one to skip MESSAGE_START character
    
    free(message);
    message = NULL;
}

void remove_client(table_entry_t *user, char *server_msg_prefixed, char **who_messages){

    int room_id = user->room_id;
    char *username = user->id;
    char *server_msg = server_msg_prefixed + 1;

    //Print message to server terminal
    printf("**%s in room #%d left the server**\n", username, room_id);

    //Print message to chat room
    sprintf(server_msg, SERVER_PREFIX "%s left the server", username);
    send_message_to_all(room_id, server_msg_prefixed, strlen(server_msg_prefixed) + 1);

    //Remove user entry from server and set who_messages for rebuild
    remove_user(&user);
    who_messages[room_id][0] = '\0';
}

static void terminate_server(int sig_num){
    //Turn echoing back on
    struct termios tc;
    tcgetattr(STDIN_FILENO, &tc);
    tc.c_lflag |= (ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &tc);
    exit(EXIT_SUCCESS);
}

void shutdown_server(char **who_messages){

    int client_socket = 0;
    int message_size = 0;
    table_entry_t *user, *tmp;
    const char *server_msg_literal = NULL;

    //Create server-shutdown message
    server_msg_literal = MESSAGE_START_STR SERVER_PREFIX "The server has been shutdown by an admin";
    message_size = strlen(server_msg_literal) + 1;

    //Free user messages, close client sockets, and delete users from hash table
    for(int room_id = 0; room_id < MAX_ROOMS; room_id++){
        HASH_ITER(hh, active_users[room_id], user, tmp){ //Uthash deletion-safe iteration
            if(user->message){
                free(user->message);
                user->message = NULL;
            }
            client_socket = user->socket_fd;
            send_message(client_socket, server_msg_literal, message_size);
            check_status(close(client_socket), "Error closing client socket");
            delete_user(&user);
        }
    }

    //Free who_message strings
    for(int i = 0; i < MAX_ROOMS; i++){
        free(who_messages[i]);
        who_messages[i] = NULL;
    }
}