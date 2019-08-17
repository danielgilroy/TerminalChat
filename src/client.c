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
    signal(SIGINT, shutdown_handler); //CTRL+C
    signal(SIGQUIT, shutdown_handler); //CTRL+BACKSLASH
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

    //Initialize ncurses chat windows and connect to server
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

    //Process outgoing messages
    outgoing_messages();

    pthread_mutex_destroy(&connected_lock);
    pthread_mutex_destroy(&print_lock);
    shutdown_chat();

    return 0;
}

void initialize_chat(){

    initscr();
    noecho();
    cbreak();
    //nocbreak();
    //raw(); 
    ////noraw();
    keypad(text_win, TRUE);

    chat_win = newwin(LINES - 1, COLS, 0, 0);
    text_win = newwin(1, COLS, LINES - 1, 0);

    //Enable scrolling for chat window
    idlok(chat_win, TRUE);
    scrollok(chat_win, TRUE);

    //Disable scrolling for text-entry window
    // idlok(text_win, FALSE);
    // scrollok(text_win, FALSE);

    idlok(text_win, FALSE);
    scrollok(text_win, FALSE);
    keypad(text_win, TRUE);

    //Show prompt message
    mvwprintw(text_win, 0, 0, INPUT_INDICATOR);

    //Get maximum input length from either screen size or buffer
    if((COLS - 11) < (MESSAGE_LENGTH - 3)){
        input_length = COLS - 11;
    }else{
        input_length = MESSAGE_LENGTH - 3; //Remove 3 for start, end, and NUL characters      
    }

    //Refresh windows so they appear on screen
    wrefresh(chat_win);
    wrefresh(text_win);
}

void initialize_connection(char *ip, int port){
    int bytes_recv;
    char response[MESSAGE_LENGTH];

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
    char server_message[MESSAGE_LENGTH + 1];
    server_message[MESSAGE_LENGTH] = '\0';
     
    while(1){

        bytes_recv = receive_message(server_message, MESSAGE_LENGTH);
    
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
    size_t message_size = 0;
    char user_message[MESSAGE_LENGTH];
    user_message[0] = '\0';

    do{

        //Ignore blank messages
        if(!get_user_message(user_message, &message_size)){
            continue;
        }

        //Move cursor to starting position and clear the line
        pthread_mutex_lock(&print_lock);
        mvwprintw(text_win, 0, 0, INPUT_INDICATOR);
        wclrtoeol(text_win);
        //wrefresh(chat_win);
        wrefresh(text_win);
        pthread_mutex_unlock(&print_lock);

        if(user_message[0] == '/'){

            /* --------------------- */
            /* Process local command */
            /* --------------------- */

            //Local command - Clear chat window
            if(strcmp(user_message, "/clear") == 0){
                werase(chat_win);
                wrefresh(chat_win);
                wrefresh(text_win);
                continue;
            }

            //Local Command - Change colours
            if(strncmp(user_message, "/colour", 7) == 0){
                //Convert british spelling "colour" to "color"
                for(int i = 5; i < message_size; i++){
                    user_message[i] = user_message[i+1];
                }
            }
            if(strncmp(user_message, "/color", cmd_length = 6) == 0){

                static int color = 0;
                start_color();
                init_pair(0, COLOR_WHITE, COLOR_BLACK);
                init_pair(1, COLOR_YELLOW, COLOR_BLUE);
                
                if(user_message[cmd_length] == '\0'){
                    color = (color + 1) % 2;
                    wbkgd(chat_win, COLOR_PAIR(color));
                }else if(strncmp(user_message + cmd_length + 1, "off", 4) == 0){
                    wbkgd(chat_win, COLOR_PAIR(0));
                    color = 0;
                }else if(strncmp(user_message + cmd_length + 1, "on", 3) == 0){
                    wbkgd(chat_win, COLOR_PAIR(1));
                    color = 1;
                }else{
                    continue;
                }

                wrefresh(chat_win);
                wrefresh(text_win);
                continue;
            }

            /* ----------------------------------------- */
            /* Or fall through to send command to server */
            /* ----------------------------------------- */
        }

        pthread_mutex_lock(&connected_lock);
        if(connected){
            pthread_mutex_unlock(&connected_lock);

            status = send_message(user_message, message_size + 1); //Plus 1 for NUL character
            //---------DEBUG---------//
            // char flip[MESSAGE_LENGTH];
            // char tmp;
            // for(int i = 0, j = message_size - 1; i <= j; i++, j--){
            //     tmp = user_message[i];
            //     user_message[i] = user_message[j];
            //     user_message[j] = tmp;
            // }
            // status = send_message(user_message, message_size + 1);
            // status = send_message(user_message, message_size + 1);
            //---------DEBUG---------//
            if(status == -1){
                perror("Error");
            }
        }
        pthread_mutex_unlock(&connected_lock);

        wrefresh(chat_win);
        wrefresh(text_win);

    }while(strcmp(user_message, "/q") && strcmp(user_message, "/quit") && strcmp(user_message, "/exit"));
  
    pthread_mutex_lock(&print_lock);
    wprintw(chat_win, "\n -Leaving chat server-\n");
    wrefresh(chat_win); 
    pthread_mutex_unlock(&print_lock);
}

bool get_user_message(char *message, size_t *message_size){

    char buffer[MESSAGE_LENGTH];
    buffer[0] = '\0';

    //Get message from user and echo to screen
    int c = 0;
    int pos = 0; //Current position
    int end = 0; //End position
    while((c = wgetch(text_win)) != '\n'){       

        //---DEBUG PRINT---//
        // mvwprintw(chat_win, 0, 0, "%d", c);
        // wrefresh(chat_win);
        //---DEBUG PRINT---//

        if(c == KEY_LEFT){
            //Move cursor left
            if(pos > 0){
                pos--;  
                pthread_mutex_lock(&print_lock);
                wmove(text_win, 0, INPUT_START + pos);
                //wrefresh(chat_win);
                //wrefresh(text_win);
                pthread_mutex_unlock(&print_lock);
            }
        }else if(c == KEY_RIGHT){
            //Move cursor right
            if(pos < end){
                pos++;
                pthread_mutex_lock(&print_lock);      
                wmove(text_win, 0, INPUT_START + pos);
                //wrefresh(chat_win);
                //wrefresh(text_win);
                pthread_mutex_unlock(&print_lock);
            }
        }else if(c == KEY_UP){
            //Get previous sent message
            end = *message_size;
            pthread_mutex_lock(&print_lock);
            for(int i = 0; i < end; i++){
                buffer[i] = message[i];
                mvwprintw(text_win, 0, INPUT_START + i, "%c", message[i]);
            }
            pos = end;
            wmove(text_win, 0, INPUT_START + pos);
            wclrtoeol(text_win);
            pthread_mutex_unlock(&print_lock);
        }else if(c == KEY_DOWN){
            //Clear current buffer
            pthread_mutex_lock(&print_lock);
            mvwprintw(text_win, 0, 0, INPUT_INDICATOR);
            wclrtoeol(text_win);
            pthread_mutex_unlock(&print_lock);
            end = 0;
            pos = 0;
        }else if(c == KEY_BACKSPACE){
            //Erase character to left of cursor
            if(pos > 0){
                //Shift remaining characters to the left
                pthread_mutex_lock(&print_lock);
                for(int i = pos; i < end; i++){
                    buffer[i - 1] = buffer[i];
                    mvwprintw(text_win, 0, INPUT_START + i - 1, "%c", buffer[i]);
                }
                pthread_mutex_unlock(&print_lock);

                //Insert empty character at the end of the message
                pos--;
                end--;
                buffer[end] = '\0';
                pthread_mutex_lock(&print_lock);
                mvwprintw(text_win, 0, INPUT_START + end, " ");
                wmove(text_win, 0, INPUT_START + pos);
                //wrefresh(chat_win);
                //wrefresh(text_win);
                pthread_mutex_unlock(&print_lock);    
            }
        }else if(c == KEY_DC){
            //Erase character to right of cursor
            if(pos < end){
                //Shift remaining characters to the left
                pthread_mutex_lock(&print_lock);
                for(int i = pos; i < end - 1; i++){
                    buffer[i] = buffer[i + 1];
                    mvwprintw(text_win, 0, INPUT_START + i, "%c", buffer[i + 1]);
                }
                pthread_mutex_unlock(&print_lock);

                //Insert empty character at the end of the message
                end--; 
                buffer[end] = '\0';
                pthread_mutex_lock(&print_lock);
                mvwprintw(text_win, 0, INPUT_START + end, " ");
                wmove(text_win, 0, INPUT_START + pos);
                //wrefresh(chat_win);
                //wrefresh(text_win);
                pthread_mutex_unlock(&print_lock); 
            }
        }else if(end < input_length && (c >= 32 && c <= 127)){
            //Shift remaining characters to the right
            pthread_mutex_lock(&print_lock);
            for(int i = end; i > pos; i--){
                buffer[i] = buffer[i - 1];
                mvwprintw(text_win, 0, INPUT_START + i, "%c", buffer[i]);
            }
            pthread_mutex_unlock(&print_lock);

            //Insert new character at the cursor position
            buffer[pos] = c;
            pthread_mutex_lock(&print_lock);
            wmove(text_win, 0, INPUT_START + pos);
            wprintw(text_win, "%c", c);
            //wrefresh(chat_win);
            //wrefresh(text_win);
            pthread_mutex_unlock(&print_lock);
            pos++;
            end++;
        }

        wrefresh(chat_win);
        wrefresh(text_win);
    }

    //NUL terminate user message and set message_size
    if(end > 0){
        buffer[end] = '\0';
        strncpy(message, buffer, end + 1);
        *message_size = end;
        return true;
    } 

    return false;
}

void print_to_chat(char * message, int bytes){

    int pos = 0;
    char c = '\0';

    while(bytes > 0){

        c = message[pos];

        if(c == MESSAGE_START){
            pthread_mutex_lock(&print_lock);
            wprintw(chat_win, "\n");
            print_time(); //Print timestamp to chat window
        }else{
            pthread_mutex_lock(&print_lock);
            wprintw(chat_win, "%c", c);
        }

        wrefresh(chat_win); 
        wrefresh(text_win); //Ensure cursor in in text window
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

void shutdown_chat(){
    endwin();
    exit(0);
}

static void shutdown_handler(int sig_num){
    shutdown_chat();
}