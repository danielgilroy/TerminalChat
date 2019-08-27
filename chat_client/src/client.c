#include "client.h"

WINDOW *chat_win;
WINDOW *text_win;
pthread_attr_t incoming_tattr;
pthread_t incoming_tid;
pthread_mutex_t connected_lock;
pthread_mutex_t incoming_lock;
pthread_cond_t incoming_cond;

int input_length = 0;

/*------Thread shared variables------*/
bool connected = false;
ssize_t bytes_recv = 0;
char server_message[MESSAGE_SIZE + 1];
/*-----------------------------------*/

int main(int argc, char *argv[]){

    server_message[MESSAGE_SIZE] = '\0';
    char *ip = DEFAULT_IP_ADDRESS;
    unsigned int port = DEFAULT_PORT_NUMBER;

    //Setup signal handlers to properly close ncurses
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
    pthread_mutex_init(&incoming_lock, NULL);
    pthread_cond_init(&incoming_cond, NULL);

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
    pthread_mutex_destroy(&incoming_lock);
    pthread_cond_destroy(&incoming_cond);
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
    wtimeout(text_win, 50); //Lower timeout if incoming messages print too slow

    //Print text-input prompt message
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

    //int bytes_recv;
    char response[MESSAGE_SIZE];

    bytes_recv = join_server(ip, port, response);    

    if(bytes_recv < 0){
        
        wprintw(chat_win, "\n\n   %s\n", response); 
        wprintw(chat_win, "      -Ensure IP address and port number are correct-\n");
        wprintw(chat_win, "            -The chat client will close shortly-\n");
        wrefresh(chat_win);
        wrefresh(text_win); //Move cursor back to text window

        sleep(10);
        shutdown_chat();
    }

    connected = true;
    print_to_chat(response, &bytes_recv);
}

void *incoming_messages(){

    ssize_t status;
    char message[MESSAGE_SIZE + 1];
    message[MESSAGE_SIZE] = '\0';
     
    while(1){

        status = receive_message(message, MESSAGE_SIZE);

        if(status <= 0){

            pthread_mutex_lock(&connected_lock);
            connected = false;
            pthread_mutex_unlock(&connected_lock);

            if(status == 0){
                wprintw(chat_win, "\n\n       -The connection to the server has been lost-\n");
                wprintw(chat_win, "           -The chat client will close shortly-\n");
            }else{
                wprintw(chat_win, "\n\n             -An unknown error has occurred-\n");
                wprintw(chat_win, "           -The chat client will close shortly-\n");
            }
            wrefresh(chat_win);
            wrefresh(text_win); //Move cursor back to text window

            sleep(10);
            shutdown_chat();  
        }

        //Copy message to ncurses buffer to be printed
        pthread_mutex_lock(&incoming_lock);
        bytes_recv = status;
        memcpy(server_message, message, bytes_recv);
        pthread_cond_wait(&incoming_cond, &incoming_lock);
        pthread_mutex_unlock(&incoming_lock);
    }
}

void outgoing_messages(){

    int status = 0;
    int cmd_length = 0;
    int password_index = 0;
    size_t message_size = 1; //Size one to hold NUL character
    char client_message[MESSAGE_SIZE];
    client_message[0] = '\0';

    do{

        pthread_mutex_lock(&incoming_lock);
        if(bytes_recv > 0){
            //Print received message to chat window
            print_to_chat(server_message, &bytes_recv);
            //Signal incoming_messages to receive next message
            pthread_cond_signal(&incoming_cond);
        }
        pthread_mutex_unlock(&incoming_lock);

        //Ignore blank and incomplete messages
        if(!get_user_message(client_message, &message_size, &password_index)){
            continue;
        }

        if(client_message[0] == '/'){

            /* --------------------- */
            /* Process local command */
            /* --------------------- */
            local_commands(client_message, message_size);

            //Or fall through to send command to server
        }

        /* --------------------------- */
        /* Send user message to server */
        /* --------------------------- */
        status = send_message(client_message, message_size);
        check_status(status, "Error sending message to server");

        //Clear message if it contains a password
        if(password_index){
            secure_zero(client_message + password_index, message_size - password_index);
            message_size = password_index + 1; //Plus one to include the NUL character
            password_index = 0;
        }

    }while(strcmp(client_message, "/q") && strcmp(client_message, "/quit") && strcmp(client_message, "/exit"));
  
    wprintw(chat_win, "\n -Leaving chat server-\n");
    wrefresh(chat_win);  
    wrefresh(text_win); //Move cursor back to text window
}

bool get_user_message(char *message, size_t *message_size, int *password_index){

    static char buffer[MESSAGE_SIZE];
    static char display[MESSAGE_SIZE];
    static char *password_ptr = NULL;

    static int buffer_char;
    static int display_char;
    static int cmd_length;
    static int pos; //Current position
    static int end; //End position

    //Ignore user input if not connected to server
    pthread_mutex_lock(&connected_lock);
    if(!connected){
        pthread_mutex_unlock(&connected_lock);
        sleep(10); //Wait for chat server to close
    }
    pthread_mutex_unlock(&connected_lock);

    //Get character from user
    buffer_char = wgetch(text_win);

    if(buffer_char == ERR){ //Return so incoming messages can be printed
        return false;
    }else if(buffer_char == KEY_LEFT){ //Move cursor left
        if(pos > 0){
            pos--;  
            wmove(text_win, 0, INPUT_START + pos);
        }
    }else if(buffer_char == KEY_RIGHT){ //Move cursor right
        if(pos < end){
            pos++;
            wmove(text_win, 0, INPUT_START + pos);
        }
    }else if(buffer_char == KEY_UP){ //Insert previous sent message into buffer
        end = *message_size - 1;
        pos = end;
        for(int i = 0; i < end; i++){
            buffer_char = message[i];
            buffer[i] = buffer_char;
            mvwprintw(text_win, 0, INPUT_START + i, "%c", buffer_char);
        }
        buffer[end] = '\0';
        if(*password_index){
            *password_index = 0;
        }
        wmove(text_win, 0, INPUT_START + pos);
        wclrtoeol(text_win);
    }else if(buffer_char == KEY_DOWN){ //Clear the current buffer
        end = 0;
        pos = 0;
        buffer[end] = '\0';
        if(*password_index){
            *password_index = 0;
        }
        wmove(text_win, 0, INPUT_START);
        wclrtoeol(text_win);
    }else if(buffer_char == KEY_BACKSPACE){ //Erase character to left of cursor
        if(pos > 0){
            //Shift remaining characters to the left
            for(int i = pos; i < end; i++){
                buffer[i - 1] = buffer[i];
                display[i - 1] = display[i];
                mvwprintw(text_win, 0, INPUT_START + i - 1, "%c", display[i]);
            }

            //Insert empty character at the end of the message
            pos--;
            end--;
            buffer[end] = '\0';
            if(*password_index && end <= *password_index){
                *password_index = 0;
            }
            mvwprintw(text_win, 0, INPUT_START + end, " ");
            wmove(text_win, 0, INPUT_START + pos);
        }
    }else if(buffer_char == KEY_DC){ //Erase character to right of cursor
        if(pos < end){
            //Shift remaining characters to the left
            for(int i = pos; i < end - 1; i++){
                buffer[i] = buffer[i + 1];
                display[i] = display[i + 1];
                mvwprintw(text_win, 0, INPUT_START + i, "%c", display[i + 1]);
            }

            //Insert empty character at the end of the message
            end--; 
            buffer[end] = '\0';
            if(*password_index && end <= *password_index){
                *password_index = 0;
            }
            mvwprintw(text_win, 0, INPUT_START + end, " ");
            wmove(text_win, 0, INPUT_START + pos);
        }
    }else if(end < input_length && (buffer_char >= 0x20 && buffer_char <= 0x7E)){ //Write character to buffer

        //Shift remaining characters to the right
        for(int i = end; i > pos; i--){
            buffer[i] = buffer[i - 1];
            display[i] = display[i - 1];
            mvwprintw(text_win, 0, INPUT_START + i, "%c", display[i]);
        }

        //Hide on-screen passwords with asterisks
        display_char = buffer_char;
        if(buffer_char != ' '){
            if(*password_index){
                display_char = '*';
            }else if(strncmp(buffer, "/nick ", cmd_length = 6) == 0
                || strncmp(buffer, "/register ", cmd_length = 10) == 0
                || strncmp(buffer, "/unregister ", cmd_length = 12) == 0){
                //Due to short circuiting, cmd_length will have the correct value
                if(password_ptr = memchr(buffer + cmd_length, ' ', end - cmd_length + 1)){
                    *password_index = password_ptr + 1 - buffer;
                    display_char = '*';
                }
            }
        }

        //Insert new character at the cursor position
        wmove(text_win, 0, INPUT_START + pos);
        wprintw(text_win, "%c", display_char);
        buffer[pos] = buffer_char;
        display[pos] = display_char;
        pos++;
        end++;
        buffer[end] = '\0';

    }else if(end > 0 && buffer_char == '\n'){ //Process completed message

        //Copy buffer to external message and set message_size
        buffer[end] = '\0';
        *message_size = end + 1;
        strncpy(message, buffer, *message_size);

        //Clear buffer if it contains a password
        if(*password_index){
            secure_zero(buffer + *password_index, *message_size - *password_index);
        }
        
        //Move cursor to starting position and clear the line
        wmove(text_win, 0, INPUT_START);
        wclrtoeol(text_win);
        wrefresh(text_win);

        //Reset buffers and positions for next message
        buffer[0] = '\0';
        display[0] = '\0';
        pos = 0;
        end = 0;

        //Return true so caller knows to process the completed message
        return true;
    }
    wrefresh(text_win);

    //Return false on incomplete/empty buffer so caller doesn't process it
    return false;
}

void local_commands(char *user_message, size_t message_size){

    int cmd_length = 0;

    //Clear chat window
    if(strcmp(user_message, "/clear") == 0){
        werase(chat_win);
        wrefresh(chat_win);
        wrefresh(text_win); //Move cursor back to text window
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

void print_to_chat(char *message, size_t *bytes){

    int pos = 0;
    int character = '\0';

    while(*bytes > 0){

        character = message[pos];
        
        if(character == MESSAGE_START){
            wprintw(chat_win, "\n");
            print_time(); //Print timestamp to chat window
        }else{
            wprintw(chat_win, "%c", character);
        }

        message++;
        (*bytes)--; 
    }

    wrefresh(chat_win); 
    wrefresh(text_win); //Move cursor back to text window
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
    wrefresh(text_win); //Move cursor back to text window
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

