#include "server_commands.h"

void whois_cmd(table_entry_t *user, char *client_msg){

    char *username = user->id;

    //Setup "/whois" command with the client's own username
    client_msg[6] = ' ';
    client_msg[7] = '\0';
    strncat(client_msg, username, MESSAGE_LENGTH);    
}

void whois_arg_cmd(table_entry_t *user, int room_id, int cmd_length, char *client_msg, char *server_msg_prefixed){

    int client_socket = user->socket_fd;
    char *username = user->id;
    char *server_msg = server_msg_prefixed + 1;
    char *target_name = NULL;

    //Get username from client's message
    get_username_and_passwords(cmd_length, client_msg, &target_name, NULL, NULL);
                            
    //Check if the username is valid
    if(!is_username_valid(target_name, server_msg)){
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }
    
    if(strcmp(target_name, username) == 0){
        sprintf(server_msg, "Server: Your address is %s:%d", user->ip, user->port);
    }else{

        //Check if client isn't an admin
        if(!user->is_admin){
            sprintf(server_msg, "Server: Only server admins can use the /whois command");
            send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
            return;
        }

        //Get user from active_users hash table
        table_entry_t *target = get_user(room_id, target_name);
        if(target == NULL){
            //Username does not exist
            sprintf(server_msg, "Server: The user \"%s\" does not exist", target_name);
            send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
            return;
        }

        sprintf(server_msg, "Server: The address of \"%s\" is %s:%d", target_name, target->ip, target->port);
    }

    send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
}

void who_cmd(int client_socket, char **who_messages){

    for(int i = 1; i < MAX_ROOMS; i++){
        //Rebuild who_messages strings if necessary
        rebuild_who_message(who_messages, i);

        //Send message containing current users in room #i
        send_message(client_socket, who_messages[i], strlen(who_messages[i]) + 1);
    }
}

void who_arg_cmd(int client_socket, char *client_msg, char *server_msg_prefixed, char **who_messages){

    char *server_msg = server_msg_prefixed + 1;

    //Check if argument after /who is valid
    if(!isdigit(client_msg[5])){
        sprintf(server_msg, "Server: Enter a valid room number (1 to %d) after /who", MAX_ROOMS - 1);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;    
    }
    
    //Get room number from user
    char *targeted_room = client_msg + 5;
    int targeted_room_id = atoi(targeted_room);
    
    //Check if chat room is valid
    if(targeted_room_id >= MAX_ROOMS || targeted_room_id < 0){
        sprintf(server_msg, "Server: Specified room doesn't exist (valid rooms are 1 to %d)", MAX_ROOMS - 1);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Rebuild who_messages strings if necessary
    rebuild_who_message(who_messages, targeted_room_id);

    //Send message containing current users in the specified room
    send_message(client_socket, who_messages[targeted_room_id], strlen(who_messages[targeted_room_id]) + 1);
}

void join_cmd(int client_socket, char *server_msg_prefixed){
    char *server_msg = server_msg_prefixed + 1;
    sprintf(server_msg, "Server: Type \"/join <room_number>\" to join a room");
    send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1); 
}

void join_arg_cmd(table_entry_t *user, int room_id, char *client_msg, char *server_msg_prefixed, char **who_messages){

    int client_socket = user->socket_fd;
    char *username = user->id;
    char *server_msg = server_msg_prefixed + 1;

    //Check if argument after /join is valid
    if(!isdigit(client_msg[6])){
        sprintf(server_msg, "Server: Enter a valid room number (0 to %d) after /join", MAX_ROOMS - 1);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;    
    }
    
    //Get new room number from user
    char *new_room = client_msg + 6;
    int new_room_id = atoi(new_room);

    //Check if chat room is valid
    if(new_room_id >= MAX_ROOMS || new_room_id < 0){
        sprintf(server_msg, "Server: Specified room doesn't exist (valid rooms are 0 to %d)", MAX_ROOMS - 1);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Check if already in the room
    if(room_id == new_room_id){
        sprintf(server_msg, "Server: You are already in room #%d", room_id);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;                                
    }

    //Print client joining message to the server's terminal
    printf("**%s changed from room #%d to room #%d**\n", username, room_id, new_room_id);

    //Send message letting clients in new room know someone joined the room
    sprintf(server_msg, "Server: User \"%s\" joined the chat room", username);
    send_message_to_all(new_room_id, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
    
    //Move user to the new chat room
    add_user(new_room_id, username, user->index, user->is_admin, user->socket_fd, user->ip, user->port);
    delete_user(room_id, user);

    //Send message letting clients in old chat room know someone changed rooms
        sprintf(server_msg, "Server: User \"%s\" switched to chat room #%d", username, new_room_id);
        send_message_to_all(room_id, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
    
    //Send message to client who just joined the room
    sprintf(server_msg, "Server: You have joined chat room #%d", new_room_id);
    send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);

    //Set both room's who_messages for rebuild
    who_messages[room_id][0] = '\0';
    who_messages[new_room_id][0] = '\0';
}

void nick_cmd(int client_socket, char *username, char *server_msg_prefixed){
    char *server_msg = server_msg_prefixed + 1;
    sprintf(server_msg, "Server: Your username is \"%s\"", username);
    send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
}

void nick_arg_cmd(table_entry_t *user, int room_id, int cmd_length, char *client_msg, char *server_msg_prefixed, char **who_messages){

    int client_socket = user->socket_fd;
    char *server_msg = server_msg_prefixed + 1;

    int status;
    char *query = NULL;
    sqlite3_stmt *stmt;

    char old_name[USERNAME_LENGTH];
    char *new_name = NULL;
    char *user_type = NULL;
    char *password = NULL;
    char *db_hashed_password = NULL;
    char hashed_password[crypto_pwhash_STRBYTES];

    strncpy(old_name, user->id, USERNAME_LENGTH);

    //Get username and one password from client's message
    get_username_and_passwords(cmd_length, client_msg, &new_name, &password, NULL);
                            
    //Check if the username is valid or restricted
    if(!is_username_valid(new_name, server_msg) || !is_username_restricted(new_name, server_msg)){
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }       

    //Check if client already has the username
    if(strcmp(old_name, new_name) == 0){
        sprintf(server_msg, "Server: Your username is already \"%s\"", new_name);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Check if username is registered in database 
    query = "SELECT password FROM users WHERE id = ?1;";
    sqlite3_prepare_v2(user_db, query, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, new_name, -1, SQLITE_STATIC);
    if((status = sqlite3_step(stmt)) == SQLITE_ROW){
        db_hashed_password = strdup((char *) sqlite3_column_text(stmt, 0));
        //printf("The SQL query returned: %s\n", db_hashed_password);
    }else if(status != SQLITE_DONE){
        fprintf(stderr, "SQL error while getting password: %s\n", sqlite3_errmsg(user_db));
    }
    sqlite3_finalize(stmt);

    if(db_hashed_password){ //Username requires a password

        //Return error message if client did not specify a password
        if(password == NULL){
            sprintf(server_msg, "Server: The username \"%s\" requires a password", new_name);
            send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
            free(db_hashed_password);
            db_hashed_password = NULL;
            return;
        }

        //Check if password is valid
        if(!is_password_valid(password, server_msg)){
            send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
            
            //Clear the plain-text password from memory
            secure_zero(client_msg, MESSAGE_LENGTH);
            free(db_hashed_password);
            db_hashed_password = NULL;
            return;     
        }

        //Compare database password with client password using libsodium
        if(crypto_pwhash_str_verify(db_hashed_password, password, strlen(password)) != 0){
            sprintf(server_msg, "Server: The specified password was incorrect");
            send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);

            //Clear the plain-text password from memory
            secure_zero(client_msg, MESSAGE_LENGTH);
            free(db_hashed_password);
            db_hashed_password = NULL;
            return;
        }

        //Check if hashed password needs to be rehashed
        if(crypto_pwhash_str_needs_rehash(db_hashed_password, PWHASH_OPSLIMIT, PWHASH_MEMLIMIT) != 0){

            //Hash password with libsodium
            if(crypto_pwhash_str(hashed_password, password, strlen(password), PWHASH_OPSLIMIT, PWHASH_MEMLIMIT) != 0) {
                fprintf(stderr, "Ran out of memory during hash function\n");
                exit(EXIT_FAILURE);
            }

            //Update the rehashed password for the registered user
            query = "UPDATE users SET password = ?1 WHERE id = ?2;";
            sqlite3_prepare(user_db, query, -1, &stmt, NULL);
            sqlite3_bind_text(stmt, 1, hashed_password, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, new_name, -1, SQLITE_STATIC);
            if(sqlite3_step(stmt) != SQLITE_DONE){
                fprintf(stderr, "SQL error while updating password: %s\n", sqlite3_errmsg(user_db));

                //Clear the plain-text password from memory
                secure_zero(client_msg, MESSAGE_LENGTH);
                free(db_hashed_password);
                db_hashed_password = NULL;
                sqlite3_finalize(stmt);
                return;
            }
            sqlite3_finalize(stmt);
        }

        free(db_hashed_password);
        db_hashed_password = NULL;

        //Get user type from the database
        query = "SELECT type FROM users WHERE id = ?1;";
        sqlite3_prepare_v2(user_db, query, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, new_name, -1, SQLITE_STATIC);
        if((status = sqlite3_step(stmt)) == SQLITE_ROW){
            user_type = strdup((char *) sqlite3_column_text(stmt, 0));
        }else if(status != SQLITE_DONE){
            fprintf(stderr, "SQL error while getting user type: %s\n", sqlite3_errmsg(user_db));    
        }
        sqlite3_finalize(stmt);
    }
    
    //Check if username is already in use on the server
    bool name_in_use = false;
    for(int i = 0; i < MAX_ROOMS; i++){
        if(get_user(i, new_name) != NULL){
            name_in_use = true;
            break;
        }
    }
    if(name_in_use){
        sprintf(server_msg, "Server: The username \"%s\" is currently in use", new_name);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        
        //Clear the plain-text password from memory
        secure_zero(client_msg, MESSAGE_LENGTH);
        return;
    }     

    //Check if database returned an admin user type
    if(user_type && strcmp(user_type, "admin") == 0){
        user->is_admin = true;
    }else{
        user->is_admin = false; 
    }
    free(user_type);
    user_type = NULL;

    //Change username in active_users hash table
    change_username(room_id, user, new_name);

    //Set who_messages for rebuild
    who_messages[room_id][0] = '\0';
    
    //Print name change message to server's terminal
    printf("**%s on socket %d changed username to %s**\n", old_name, client_socket, new_name);
    
    //Send name change message to all clients if not in lobby
    if(room_id != LOBBY_ROOM_ID){
        sprintf(server_msg, "Server: %s changed their name to %s", old_name, new_name);
        send_message_to_all(room_id, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
    }else{
        sprintf(server_msg, "Server: Your username has been changed to \"%s\"", new_name);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);  
    }

    //Clear the plain-text password from memory
    secure_zero(client_msg, MESSAGE_LENGTH);
}

void where_cmd(int client_socket, int room_id, char *server_msg_prefixed){
    char *server_msg = server_msg_prefixed + 1;
    if(room_id == 0){
        sprintf(server_msg, "Server: You are currently in the lobby");
    }else{
        sprintf(server_msg, "Server: You are currently in chat room #%d", room_id);
    }
    send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
}

void where_arg_cmd(int client_socket, int cmd_length, char *client_msg, char *server_msg_prefixed){

    char *server_msg = server_msg_prefixed + 1;
    char *target_name = NULL;

    //Get username from client message
    get_username_and_passwords(cmd_length, client_msg, &target_name, NULL, NULL);

    //Check if the username is valid
    if(!is_username_valid(target_name, server_msg)){
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }     

    //Assume user is not on the server
    sprintf(server_msg, "Server: \"%s\" is currently not on the server", target_name);

    //Look for user in lobby and change the message if located
    if(get_user(LOBBY_ROOM_ID, target_name) != NULL){
        sprintf(server_msg, "Server: \"%s\" is currently in the lobby", target_name);
    }else{
        //Look for user in every chat room and change the message if located    
        for(int i = 1; i < MAX_ROOMS; i++){
            if(get_user(i, target_name) != NULL){
                sprintf(server_msg, "Server: \"%s\" is currently in chat room #%d", target_name, i);
                break;
            }
        }
    }

    //Inform client about the specified user
    send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
}

void kick_cmd(int client_socket, char *server_msg_prefixed){
    char *server_msg = server_msg_prefixed + 1;
    sprintf(server_msg, "Server: Type \"/kick <username>\" to kick users");
    send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1); 
}

void kick_arg_cmd(table_entry_t *user, table_entry_t *tmp, int room_id, int cmd_length, char *client_msg, char *server_msg_prefixed, char **who_messages){

    int client_socket = user->socket_fd;
    char *username = user->id;
    char *server_msg = server_msg_prefixed + 1;
    char *target_name = NULL;

    //Check if client isn't an admin
    if(!user->is_admin){
        sprintf(server_msg, "Server: Only server admins can use the /kick command");
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Get username from client's message
    get_username_and_passwords(cmd_length, client_msg, &target_name, NULL, NULL);

    //Check if the username is valid
    if(!is_username_valid(target_name, server_msg)){
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Prevent client from kicking themself
    if(strcmp(username, target_name) == 0){
        sprintf(server_msg, "Server: Using /kick on yourself is prohibited");
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Look for user and perform the kick if located
    int target_room;
    table_entry_t *targeted_user;
    for(target_room = 0; target_room < MAX_ROOMS; target_room++){
        if((targeted_user = get_user(target_room, target_name)) != NULL){

            //Get tmp's hh.next for hash table itteration if removing tmp
            if(tmp == targeted_user){
                tmp = tmp->hh.next; //Avoids accessing removed user
            }

            //Inform targeted_user that they have been kicked
            sprintf(server_msg, "Server: You have been kicked from the server");
            send_message(targeted_user->socket_fd, server_msg_prefixed, strlen(server_msg_prefixed) + 1);

            //Remove client entry from server
            remove_user(target_room, targeted_user);

            //Set who_messages for rebuild
            who_messages[target_room][0] = '\0';

            break;
        }
    }

    if(targeted_user != NULL){
        //Print kick message to server's terminal
        printf("**%s in room #%d kicked from the server**\n", target_name, target_room);

        //Inform the chat room about the kick
        sprintf(server_msg, "Server: \"%s\" has been kicked from the server", target_name);
        send_message_to_all(target_room, server_msg_prefixed, strlen(server_msg_prefixed) + 1);

        //Also inform client if they are in a different room or the lobby
        if(room_id != target_room || target_room == LOBBY_ROOM_ID){
            send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        }
    }else{
        //Inform client that user was not found
        sprintf(server_msg, "Server: \"%s\" is currently not on the server", target_name);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
    }
}

void register_cmd(int client_socket, char *server_msg_prefixed){
    char *server_msg = server_msg_prefixed + 1;
    sprintf(server_msg, "Server: Type \"/register <username> <password> <password>\" to register");
    send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1); 
}

void register_arg_cmd(table_entry_t *user, int cmd_length, char *client_msg, char *server_msg_prefixed){

    int client_socket = user->socket_fd;
    char *username = user->id;
    char *server_msg = server_msg_prefixed + 1;

    int status;
    char *query = NULL;
    sqlite3_stmt *stmt;

    char *new_name = NULL;
    char *password = NULL;
    char *password2 = NULL;
    char hashed_password[crypto_pwhash_STRBYTES];
    bool user_exists = false;

    //Get username and passwords from client's message
    get_username_and_passwords(cmd_length, client_msg, &new_name, &password, &password2);

    //Check if the username is valid or restricted
    if(!is_username_valid(new_name, server_msg) || !is_username_restricted(new_name, server_msg)){
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }       

    //Check if passwords are valid
    if(!are_passwords_valid(password, password2, server_msg)){
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;  
    }

    //Hash password with libsodium
    if (crypto_pwhash_str(hashed_password, password, strlen(password), PWHASH_OPSLIMIT, PWHASH_MEMLIMIT) != 0) {
        fprintf(stderr, "Ran out of memory during hash function\n");
        exit(EXIT_FAILURE);
    }
        
    //Check if username already exists in database
    query = "SELECT id FROM users WHERE id = ?1;";
    sqlite3_prepare_v2(user_db, query, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, new_name, -1, SQLITE_STATIC);
    if((status = sqlite3_step(stmt)) == SQLITE_ROW){
        user_exists = true;
    }else if(status != SQLITE_DONE){
        fprintf(stderr, "SQL error while checking if username exists: %s\n", sqlite3_errmsg(user_db));
    }
    sqlite3_finalize(stmt);
    
    if(user_exists){
        
        //Check if client is currently the registered database user
        if(strcmp(username, new_name) == 0){

            //Change password for the registered user
            query = "UPDATE users SET password = ?1 WHERE id = ?2;";
            sqlite3_prepare_v2(user_db, query, -1, &stmt, NULL);
            sqlite3_bind_text(stmt, 1, hashed_password, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
            if(sqlite3_step(stmt) != SQLITE_DONE){
                fprintf(stderr, "SQL error while changing user password: %s\n", sqlite3_errmsg(user_db));
            }else{
                //Print password change message to server's terminal
                printf("**%s on socket %d changed their password**\n", username, client_socket);
                
                //Inform client of password change
                sprintf(server_msg, "Server: Your username password has been changed");
                send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
            }
            sqlite3_finalize(stmt);

        }else{
            //Inform client that username is already registered
            sprintf(server_msg, "Server: The username \"%s\" is already registered", new_name);
            send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        }

    }else{

        //Register username into database
        query = "INSERT INTO users(id, password, type) VALUES(?1, ?2, 'user');";
        sqlite3_prepare_v2(user_db, query, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, new_name, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hashed_password, -1, SQLITE_STATIC);
        if(sqlite3_step(stmt) != SQLITE_DONE){
                fprintf(stderr, "SQL error while registering username: %s\n", sqlite3_errmsg(user_db));
        }else{
            //Print username registration message to server's terminal
            printf("**%s on socket %d registered username %s**\n", username, client_socket, new_name);

            //Inform client of username registration
            sprintf(server_msg, "Server: You have registered the username \"%s\"", new_name);
            send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);    
        }
        sqlite3_finalize(stmt);
    }

    //Clear the plain-text passwords from memory
    secure_zero(client_msg, MESSAGE_LENGTH);
}

void admin_cmd(int client_socket, char *server_msg_prefixed){
    char *server_msg = server_msg_prefixed + 1;
    sprintf(server_msg, "Server: Type \"/admin <username>\" to change account type");
    send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
}

void admin_arg_cmd(table_entry_t *user, int cmd_length, char *client_msg, char *server_msg_prefixed){
    
    int client_socket = user->socket_fd;
    char *username = user->id;
    char *server_msg = server_msg_prefixed + 1;

    int status;
    char *query = NULL;
    sqlite3_stmt *stmt;

    char *target_name = NULL;
    char *user_type = NULL;
    char *type_change = NULL;

    //Allow usage for all admin accounts
    /*if(!user->is_admin){
        sprintf(server_msg, "Server: Only server admins can use the /admin command");
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }*/

    //Allow usage for main admin account only
    if(strcmp(username, "Admin") != 0){
        sprintf(server_msg, "Server: Only the \"Admin\" account can use the /admin command");
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Get username from client's message
    get_username_and_passwords(cmd_length, client_msg, &target_name, NULL, NULL);

    //Check if the username is valid
    if(!is_username_valid(target_name, server_msg)){
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }   

    //Check if targeted user is the client
    if(strcmp(target_name, username) == 0){
        //Inform client that changing their own account is prohibited
        sprintf(server_msg, "Server: Chaning your own account type is prohibited");
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Check if targeted user is the main admin account
    if(strcmp(target_name, "Admin") == 0){
        //Inform client that changing the main admin account is prohibited
        sprintf(server_msg, "Server: Changing the main admin account type is prohibited");
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return;
    }

    //Check if username is registered in database and get user type
    query = "SELECT type FROM users WHERE id = ?1;";
    sqlite3_prepare_v2(user_db, query, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, target_name, -1, SQLITE_STATIC);
    if((status = sqlite3_step(stmt)) == SQLITE_ROW){
        user_type = strdup((char *) sqlite3_column_text(stmt, 0));
    }else if(status != SQLITE_DONE){
        fprintf(stderr, "SQL error while getting user type: %s\n", sqlite3_errmsg(user_db));
    }
    sqlite3_finalize(stmt);

    if(user_type){
        
        //Get the account type to switch to
        if(strcmp(user_type, "admin") == 0){
            type_change = "user";
        }else{
            type_change = "admin";
        }

        free(user_type);
        user_type = NULL;

        //Switch targeted user's account type in database
        query = "UPDATE users SET type = ?1 WHERE id = ?2;";
        sqlite3_prepare_v2(user_db, query, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, type_change, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, target_name, -1, SQLITE_STATIC);
        if(sqlite3_step(stmt) != SQLITE_DONE){
            fprintf(stderr, "SQL error while changing user type: %s\n", sqlite3_errmsg(user_db));
            sqlite3_finalize(stmt); 
            return;
        }
        sqlite3_finalize(stmt);

        //Look for user on server and change account type if located
        table_entry_t *target_user = NULL;
        for(int i = 0; i < MAX_ROOMS; i++){
            if((target_user = get_user(i, target_name)) != NULL){

                //Switch account type
                target_user->is_admin = !target_user->is_admin;

                //Inform targeted user of account type change
                sprintf(server_msg, "Server: Your account has changed to \"%s\" type", type_change);
                send_message(target_user->socket_fd, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
                break;
            }
        }

        //Print account type change message to server's terminal
        printf("**Account \"%s\" changed to \"%s\" type**\n", target_name, type_change);
        
        //Inform client of account type change
        sprintf(server_msg, "Server: Account \"%s\" changed to \"%s\" type", target_name, type_change);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);

    }else{
        //Inform client that the targeted user is not registered
        sprintf(server_msg, "Server: The username \"%s\" is not registered", target_name);
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
    }
}

bool die_cmd(table_entry_t *user, char *server_msg_prefixed){

    int client_socket = user->socket_fd;
    char *server_msg = server_msg_prefixed + 1;

    //Check if user isn't an admin
    if(!user->is_admin){
        sprintf(server_msg, "Server: Only server admins can use the /die command");
        send_message(client_socket, server_msg_prefixed, strlen(server_msg_prefixed) + 1);
        return false;
    }

    //Flag server for shutdown
    return true;
}