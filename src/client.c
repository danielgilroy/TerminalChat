#include "client.h"

WINDOW *chat_win;
pthread_t incoming_tid;
pthread_mutex_t connected_lock;
pthread_mutex_t print_lock;
bool connected = false;
int input_length = 0;

int main(int argc, char *argv[]){

    char *ip = DEFAULT_IP_ADDRESS;
    unsigned int port = DEFAULT_PORT_NUMBER;

    //Setup signal handlers for CTRL+C and CTRL+BACKSLASH
    signal(SIGINT, shutdown_handler); 
    signal(SIGQUIT, shutdown_handler); 

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

    //Setup mutex locks and create thread for incoming messages
    pthread_mutex_init(&connected_lock, NULL);
    pthread_mutex_init(&print_lock, NULL);
    pthread_create(&incoming_tid, NULL, incoming_messages, NULL);

    //Detach incoming message thread
    if(pthread_detach(incoming_tid)){
        perror("Thread detaching error");
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
    noraw();
    //raw();
    //cbreak();
    //nocbreak(); 
    keypad(stdscr, TRUE);

    chat_win = newwin(LINES-1, COLS, 0, 0);

    //Enable scrolling for chat window
    idlok(chat_win, TRUE);
    scrollok(chat_win, TRUE);

    //Show prompt message
    mvwprintw(stdscr, LINES-1, 0, "Send> ");

    //Get maximum input length
    if((COLS - 11) < (MESSAGE_LENGTH - 3)){
        input_length = COLS - 11;
    }else{
        input_length = MESSAGE_LENGTH - 3;        
    }

    //Refresh windows so they appear on screen
    wrefresh(chat_win);
    wrefresh(stdscr);
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

    int status;
    char user_message[MESSAGE_LENGTH];
    size_t message_length;

    do{
        
        //Get input string from the user
        getnstr(user_message, input_length);

        //Move cursor to starting position and clear the line
        pthread_mutex_lock(&print_lock);
        wmove(stdscr, LINES - 1, 6);
        clrtoeol();
        wrefresh(chat_win);
        wrefresh(stdscr);
        pthread_mutex_unlock(&print_lock);

        if(user_message[0] == '\0'){
            //Message is blank so ignore it
            continue;
        }else if(user_message[0] == '/'){

            /* --------------------- */
            /* Process local command */
            /* --------------------- */

            //Local command - Clear chat window
            if(strcmp(user_message, "/clear") == 0){
                werase(chat_win);
                wrefresh(chat_win);
                wrefresh(stdscr);
                continue;
            }

            //Local Command - Change colours
            if(strncmp(user_message, "/colour ", 7) == 0){
                //Convert british spelling "colour" to "color"
                for(int i = 5; i < strlen(user_message); i++){
                    user_message[i] = user_message[i+1];
                }
            }
            if(strncmp(user_message, "/color ", 6) == 0){

                start_color();
                init_pair(1, COLOR_WHITE, COLOR_BLACK);
                init_pair(2, COLOR_YELLOW, COLOR_BLUE);
                
                if(strncmp(user_message + 7, "off", 3) == 0){
                    wbkgd(chat_win, COLOR_PAIR(1));
                }
                if(strncmp(user_message + 7, "on", 2) == 0){
                    wbkgd(chat_win, COLOR_PAIR(2));
                }

                wrefresh(chat_win);
                wrefresh(stdscr);
                continue;
            }

            /* ----------------------------------------- */
            /* Or fall through to send command to server */
            /* ----------------------------------------- */
        }

        //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
        //Add a control character to the start of message so we know when it's
        //a new message since the message may be split up over multiple packets
        //message[0] = 0x02; //Start of text control character
        //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

        pthread_mutex_lock(&connected_lock);
        if(connected){
            pthread_mutex_unlock(&connected_lock);

            message_length = strlen(user_message);
            status = send_message(user_message, message_length + 1);
            status = send_message(user_message, message_length + 1);
            if(status == -1){
                perror("Error");
            }
        }
        pthread_mutex_unlock(&connected_lock);

        wrefresh(chat_win);
        wrefresh(stdscr);

    }while(strcmp(user_message, "/q") && strcmp(user_message, "/quit") && strcmp(user_message, "/exit"));
  
    wprintw(chat_win, "\n -Leaving chat server-\n");
    wrefresh(chat_win); 
}

void print_to_chat(char * message, int bytes){

    int length = 0;
    while(bytes > 0){
        if(message[0] == MESSAGE_START){
            pthread_mutex_lock(&print_lock);
            wprintw(chat_win, "\n");
            print_time(); 
            wrefresh(chat_win); //Show timestamp on chat window
            wrefresh(stdscr); //Ensure cursor in text window is show
            pthread_mutex_unlock(&print_lock);
            message++;
            bytes--;
        }
        pthread_mutex_lock(&print_lock);
        wprintw(chat_win, "%s", message);
        wrefresh(chat_win); //Show message on chat window
        wrefresh(stdscr); //Ensure cursor in text window is show
        pthread_mutex_unlock(&print_lock);
        length = strlen(message); 
        message += length + 1; //Move to next string - Add one to skip over the null character
        if(length == bytes){
            bytes -= length; //Remaining bytes without a null character (the remainder is in another packet)
        }else{
            bytes -= length + 1; //Remaining bytes with a null character (the string is finished in this packet)
        }
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
    wrefresh(stdscr); 
}

void shutdown_chat(){
    endwin();
    exit(0);
}

static void shutdown_handler(int sig_num){
    shutdown_chat();
}