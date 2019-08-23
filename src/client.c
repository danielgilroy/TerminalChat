#include "client.h"

WINDOW *chat_win;
WINDOW *text_win;
pthread_attr_t incoming_tattr;
pthread_t incoming_tid;
pthread_mutex_t connected_lock;
pthread_mutex_t print_lock;
bool connected = false;
int input_length = 0;

int main(int argc, char *argv[]){

    char *ip = DEFAULT_IP_ADDRESS;
    unsigned int port = DEFAULT_PORT_NUMBER;

    //Setup signal handlers to properly clost ncurses
    signal(SIGINT, shutdown_handler); //CTRL + C
    signal(SIGQUIT, shutdown_handler); //CTRL + BACKSLASH
    signal(SIGSEGV, shutdown_handler); //Memory access violation

    //Get user-specified IP and port from CLI arguments
    if(argc > 2){
        ip = argv[1];
        port = atoi(argv[2]);
    }else if(argc > 1){
        //Check if the first argument is an IP address
        char *first_argument = argv[1];
        if(strchr(first_argument, '.') || strchr(first_argument, ':')){
            ip = first_argument;
        }else{
            port = atoi(first_argument);
        }
    }

    initialize_chat();
    initialize_connection(ip, port);

    //Initialize mutex locks
    pthread_mutex_init(&connected_lock, NULL);
    pthread_mutex_init(&print_lock, NULL);

    //Create thread for incoming messages in a detached state
    if(pthread_attr_init(&incoming_tattr)){
        perror("Error initializing pthread attribute");
        exit(EXIT_FAILURE);
    }
    if(pthread_attr_setdetachstate(&incoming_tattr, PTHREAD_CREATE_DETACHED)){
        perror("Error setting pthread detach state");
        exit(EXIT_FAILURE);
    }
    if(pthread_create(&incoming_tid, &incoming_tattr, incoming_messages, NULL)){
        perror("Error creating pthread");
        exit(EXIT_FAILURE);
    }
    if(pthread_attr_destroy(&incoming_tattr)){
        perror("Error destroying pthread attribute");
        exit(EXIT_FAILURE);
    }

    outgoing_messages();

    pthread_mutex_destroy(&connected_lock);
    pthread_mutex_destroy(&print_lock);
    shutdown_chat();

    return 0;
}

void initialize_chat(){

    initscr();
    check_status(noecho(), "Error setting noecho state for ncurses");
    check_status(cbreak(), "Error setting cbreak state for ncurses");
    
    //Create new windows for chat text and text entry
    chat_win = newwin(LINES - 1, COLS, 0, 0);
    text_win = newwin(1, COLS, LINES - 1, 0);

    //Enable scrolling for chat window
    idlok(chat_win, TRUE);
    scrollok(chat_win, TRUE);

    //Disable scrolling for text-entry window and enable keypad
    scrollok(text_win, FALSE);
    check_status(keypad(text_win, TRUE), "Error enabling keypad for text window");

    //Show prompt message
    mvwprintw(text_win, 0, 0, INPUT_INDICATOR);

    //Get maximum input length from either screen size or buffer
    if((COLS - 11) < (MESSAGE_SIZE - 2)){
        input_length = COLS - 11;
    }else{
        input_length = MESSAGE_SIZE - 2; //Remove 2 for start and end control characters      
    }

    //Refresh windows so they appear on screen
    wrefresh(chat_win);
    wrefresh(text_win);
}

void initialize_connection(char *ip, int port){

    int bytes_recv;
    char response[MESSAGE_SIZE];

    bytes_recv = join_server(ip, port, response);    

    if (bytes_recv < 0){
        wprintw(chat_win, "\n\n   %s\n", response); 
        wprintw(chat_win, "      -Ensure IP address and port number are correct-\n");
        wprintw(chat_win, "            -The chat client will close shortly-\n");
        wrefresh(chat_win);
        sleep(10);
        shutdown_chat();
    }

    connected = true;
    print_to_chat(response, bytes_recv);
}

void *incoming_messages(){

    int bytes_recv;
    char server_message[MESSAGE_SIZE + 1];
    server_message[MESSAGE_SIZE] = '\0';
     
    while(1){

        bytes_recv = receive_message(server_message, MESSAGE_SIZE);
    
        if(bytes_recv <= 0){
            if(bytes_recv == 0){
                wprintw(chat_win, "\n\n       -The connection to the server has been lost-\n");
                wprintw(chat_win, "          -The chat client will close shortly-\n");
            }else{
                wprintw(chat_win, "\n\n  -An unknown error has occurred-\n");
                wprintw(chat_win, "-The chat client will close shortly-\n");
            }
            
            wrefresh(chat_win);
            pthread_mutex_lock(&connected_lock);
            connected = false;
            pthread_mutex_unlock(&connected_lock);
            sleep(10);
            shutdown_chat();  
        }

        print_to_chat(server_message, bytes_recv);
    }
}

void outgoing_messages(){

    int status = 0;
    int cmd_length = 0;
    size_t message_size = 1; //Size one to hold NUL character
    char message[MESSAGE_SIZE];
    message[0] = '\0';

    do{

        //Ignore blank messages
        if(!get_user_message(message, &message_size)){
            continue;
        }

        //Move cursor to starting position and clear the line
        pthread_mutex_lock(&print_lock);
        mvwprintw(text_win, 0, 0, INPUT_INDICATOR);
        wclrtoeol(text_win);
        wrefresh(text_win);
        pthread_mutex_unlock(&print_lock);

        if(message[0] == '/'){

            /* --------------------- */
            /* Process local command */
            /* --------------------- */
            local_commands(message, message_size);

            //Or fall through to send command to server
        }

        /* --------------------------- */
        /* Send user message to server */
        /* --------------------------- */

        pthread_mutex_lock(&connected_lock);
        if(connected){
            pthread_mutex_unlock(&connected_lock);

            status = send_message(message, message_size);
            check_status(status, "Error sending message to server");
        }
        pthread_mutex_unlock(&connected_lock);

        wrefresh(chat_win);
        wrefresh(text_win);

        if(strncmp(message, "/nick ", cmd_length = 6) == 0){
            //Clear message since it may contain passwords
            secure_zero(message + cmd_length, message_size - cmd_length);
            //strncpy(message, "/nick ", cmd_length + 1);
            message_size = cmd_length + 1; //Plus one to include NUL character
        }else if(strncmp(message, "/register ", cmd_length = 10) == 0){
            //Clear message since it may contain passwords
            secure_zero(message + cmd_length, message_size - cmd_length);
            message_size = cmd_length + 1; //Plus one to include NUL character
        }

    }while(strcmp(message, "/q") && strcmp(message, "/quit") && strcmp(message, "/exit"));
  
    pthread_mutex_lock(&print_lock);
    wprintw(chat_win, "\n -Leaving chat server-\n");
    wrefresh(chat_win); 
    pthread_mutex_unlock(&print_lock);
}

bool get_user_message(char *message, size_t *message_size){

    char buffer[MESSAGE_SIZE];
    char display[MESSAGE_SIZE];
    buffer[0] = '\0';
    display[0] = '\0';

    int buffer_char = 0;
    int display_char = 0;
    int cmd_length = 0;
    int pos = 0; //Current position
    int end = 0; //End position

    //Get message from user and echo to screen
    while((buffer_char = wgetch(text_win)) != '\n'){       

        if(buffer_char == KEY_LEFT){ //Move cursor left
            if(pos > 0){
                pos--;  
                pthread_mutex_lock(&print_lock);
                wmove(text_win, 0, INPUT_START + pos);
                wrefresh(text_win);
                pthread_mutex_unlock(&print_lock);
            }
        }else if(buffer_char == KEY_RIGHT){ //Move cursor right
            if(pos < end){
                pos++;
                pthread_mutex_lock(&print_lock);      
                wmove(text_win, 0, INPUT_START + pos);
                wrefresh(text_win);
                pthread_mutex_unlock(&print_lock);
            }
        }else if(buffer_char == KEY_UP){ //Insert previous sent message into buffer
            end = *message_size - 1;
            pos = end;
            pthread_mutex_lock(&print_lock);
            for(int i = 0; i < end; i++){
                buffer_char = message[i];
                buffer[i] = buffer_char;
                display_char = buffer_char;
                mvwprintw(text_win, 0, INPUT_START + i, "%c", display_char);
            }
            wmove(text_win, 0, INPUT_START + pos);
            wclrtoeol(text_win);
            wrefresh(text_win);
            pthread_mutex_unlock(&print_lock);
        }else if(buffer_char == KEY_DOWN){ //Clear the current buffer
            end = 0;
            pos = 0;
            //memset(buffer, '\0', 11); //Erase command from buffer 
            buffer[0] = '\0';
            display[end] = '\0';
            pthread_mutex_lock(&print_lock);
            mvwprintw(text_win, 0, 0, INPUT_INDICATOR);
            wclrtoeol(text_win);
            wrefresh(text_win);
            pthread_mutex_unlock(&print_lock);
        }else if(buffer_char == KEY_BACKSPACE){ //Erase character to left of cursor
            if(pos > 0){
                //Shift remaining characters to the left
                pthread_mutex_lock(&print_lock);
                for(int i = pos; i < end; i++){
                    buffer[i - 1] = buffer[i];
                    display[i - 1] = display[i];
                    mvwprintw(text_win, 0, INPUT_START + i - 1, "%c", display[i]);
                }
                pthread_mutex_unlock(&print_lock);

                //Insert empty character at the end of the message
                pos--;
                end--;
                buffer[end] = '\0';
                display[end] = '\0';
                pthread_mutex_lock(&print_lock);
                mvwprintw(text_win, 0, INPUT_START + end, " ");
                wmove(text_win, 0, INPUT_START + pos);
                wrefresh(text_win);
                pthread_mutex_unlock(&print_lock);    
            }
        }else if(buffer_char == KEY_DC){ //Erase character to right of cursor
            if(pos < end){
                //Shift remaining characters to the left
                pthread_mutex_lock(&print_lock);
                for(int i = pos; i < end - 1; i++){
                    buffer[i] = buffer[i + 1];
                    display[i] = display[i + 1];
                    mvwprintw(text_win, 0, INPUT_START + i, "%c", display[i + 1]);
                }
                pthread_mutex_unlock(&print_lock);

                //Insert empty character at the end of the message
                end--; 
                buffer[end] = '\0';
                display[end] = '\0';
                pthread_mutex_lock(&print_lock);
                mvwprintw(text_win, 0, INPUT_START + end, " ");
                wmove(text_win, 0, INPUT_START + pos);
                wrefresh(text_win);
                pthread_mutex_unlock(&print_lock); 
            }
        }else if(end < input_length && (buffer_char >= 32 && buffer_char <= 127)){ //Write character to buffer
            //Shift remaining characters to the right
            pthread_mutex_lock(&print_lock);
            for(int i = end; i > pos; i--){
                buffer[i] = buffer[i - 1];
                display[i] = display[i - 1];
                mvwprintw(text_win, 0, INPUT_START + i, "%c", display[i]);
            }
            pthread_mutex_unlock(&print_lock);

            //Hide on-screen passwords with asterisks
            display_char = buffer_char;
            if(display_char != ' ' && strncmp(buffer, "/nick ", cmd_length = 6) == 0){
                if(memchr(buffer + cmd_length, ' ', end - cmd_length + 1)){
                    display_char = '*';
                }
            }else if(display_char != ' ' && strncmp(buffer, "/register ", cmd_length = 10) == 0){
                if(memchr(buffer + cmd_length, ' ', end - cmd_length + 1)){
                    display_char = '*';
                }
            }

            //Insert new character at the cursor position
            pthread_mutex_lock(&print_lock);
            wmove(text_win, 0, INPUT_START + pos);
            wprintw(text_win, "%c", display_char);
            wrefresh(text_win);
            pthread_mutex_unlock(&print_lock);
            buffer[pos] = buffer_char;
            display[pos] = display_char;
            pos++;
            end++;
            buffer[end] = '\0';
            display[end] = '\0';
        }
    }

    //Copy buffer to external message and set message_size
    if(end > 0){
        *message_size = end + 1;
        strncpy(message, buffer, *message_size);
        //Clear buffer since it may contain passwords
        secure_zero(buffer, *message_size);
        return true;
    } 

    //Return false on empty buffer
    return false;
}

void local_commands(char *user_message, size_t message_size){

    int cmd_length = 0;

    //Clear chat window
    if(strcmp(user_message, "/clear") == 0){
        werase(chat_win);
        wrefresh(chat_win);
        wrefresh(text_win);
        return;
    }

    //Change window colours
    if(strncmp(user_message, "/colour", 7) == 0){
        //Convert british spelling "colour" to "color"
        for(int i = 5; i < message_size; i++){
            user_message[i] = user_message[i+1];
        }
    }
    if(strncmp(user_message, "/color", cmd_length = 6) == 0){

        if(!has_colors()){
            return;
        }

        use_default_colors();
        start_color();
        init_pair(0, -1, -1); //Default colours
        init_pair(1, COLOR_WHITE, COLOR_BLUE);
        init_pair(2, COLOR_WHITE, COLOR_BLACK);
        static int color = 0;
        
        if(user_message[cmd_length] == '\0'){
            color = (color + 1) % 2;
            wbkgd(chat_win, COLOR_PAIR(color)); //Colour pair 0 or 1
            wbkgd(text_win, COLOR_PAIR(color * 2)); //Colour pair 0 or 2
        }else if(strncmp(user_message + cmd_length + 1, "off", 4) == 0){
            wbkgd(chat_win, COLOR_PAIR(0));
            wbkgd(text_win, COLOR_PAIR(0));
            color = 0;
        }else if(strncmp(user_message + cmd_length + 1, "on", 3) == 0){
            wbkgd(chat_win, COLOR_PAIR(1));
            wbkgd(text_win, COLOR_PAIR(2));
            color = 1;
        }else{
            return;
        }

        wrefresh(chat_win);
        wrefresh(text_win);
        return;
    }
}

void print_to_chat(char * message, int bytes){

    int pos = 0;
    char c = '\0';

    while(bytes > 0){

        c = message[pos];

        pthread_mutex_lock(&print_lock);
        if(c == MESSAGE_START){
            wprintw(chat_win, "\n");
            print_time(); //Print timestamp to chat window
        }else{
            wprintw(chat_win, "%c", c);
        }

        wrefresh(chat_win); 
        wrefresh(text_win); //Ensure cursor is in text window
        pthread_mutex_unlock(&print_lock);
        message++;
        bytes--; 
    }
}

void print_time(){
    time_t raw_time = time(NULL);
    struct tm *cur_time;

    //Get local time
    time(&raw_time);
    cur_time = localtime(&raw_time);  

    //Print time to chat window at current cursor location
    wprintw(chat_win, "%02d:%02d ", cur_time->tm_hour, cur_time->tm_min);
    wrefresh(chat_win); 
    wrefresh(text_win); 
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

void shutdown_chat(){
    check_status(endwin(), "Error closing ncurses");
    exit(0);
}

static void shutdown_handler(int sig_num){
    shutdown_chat();
}

