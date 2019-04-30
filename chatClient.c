#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <pthread.h>
#include <signal.h>
#include <ncurses.h>

#include "tcpClient.h"

#define MESSAGE_LENGTH 256
#define MESSAGE_START 0x02

void initializeChat();
void initializeConnection();
void terminateChat();
void terminateChatNow();
void *incomingMessages();
void outgoingMessages();
void printToChat(char *, int);
void printTime();
static void handler(int);
void *printMessage();

WINDOW *chat_win;
pthread_t tid;

int main(){

    initializeChat();
    initializeConnection();
        
    //Setup signal handler and create thread for incoming messages
    signal(SIGUSR1, handler);
    pthread_create(&tid, NULL, incomingMessages, NULL);

    outgoingMessages();
    terminateChat();

    return 0;
}

void initializeChat(){

    initscr();
    raw();
    //noraw();
    //cbreak();
    //nocbreak(); 
    keypad(stdscr, TRUE);

    chat_win = newwin(LINES-1, COLS, 0, 0);

    //Enable scrolling for chat window
    idlok(chat_win, TRUE);
    scrollok(chat_win, TRUE);

    //Show prompt message
    mvwprintw(stdscr, LINES-1, 0, "Send> ");

    //Refresh windows so they appear on screen
    wrefresh(chat_win);
    wrefresh(stdscr);
}

void initializeConnection(){
    int recv_status;
    char response[MESSAGE_LENGTH];

    recv_status = joinServer(response);    

    if (recv_status < 0){
        wprintw(chat_win, "\n\n    -There was an error connecting to the server-\n");
        wprintw(chat_win, "        -The chat client will close shortly-\n");
        wrefresh(chat_win);
        sleep(3);
        terminateChat();
    }

    printToChat(response, recv_status);
}

void terminateChat(){

    if(tid){
        pthread_kill(tid, SIGUSR1); //Send signal for thread to exit
        pthread_join(tid, NULL); //Wait for thread to exit
    }

    endwin();
    exit(0);
}

/* TEMPORARY FIX - HANDLE CLOSING OF THREAD BETTER WHEN CALLED FROM WIHIN THAT THREAD */
void terminateChatNow(){
    endwin();
    exit(0);
}

void *incomingMessages(){

    int recv_status;
    char server_message[MESSAGE_LENGTH];
     
    while(1){

        recv_status = receiveMessage(server_message, MESSAGE_LENGTH);
    
        if(recv_status == 0){
            wprintw(chat_win, "\n\n       -The connection to the server has been lost-\n");
            wprintw(chat_win, "          -Type /quit to close the chat client-\n");
            wrefresh(chat_win);
            return NULL;  
        }else if(recv_status == -1){
            wprintw(chat_win, "\n\n  -An unknown error has occurred-\n");
            wprintw(chat_win, "-The chat client will close shortly-\n");
            wrefresh(chat_win);
            sleep(5);
            terminateChatNow();  
        }

        static int k = 0;
        //wprintw(chat_win, "\nRECV %d", k);
        k++;
        wrefresh(chat_win); 

        printToChat(server_message, recv_status);
    }
}

void outgoingMessages(){

    int status;
    char user_message[MESSAGE_LENGTH];
    size_t message_length;

    do{

        //Get input string from the user
        getnstr(user_message, COLS - 5);

        //Move cursor to starting position and clear the line
        wmove(stdscr, LINES-1, 6);
        clrtoeol();
        wrefresh(chat_win);
        wrefresh(stdscr);

        if(user_message[0] == '\0'){
            //Message is blank so ignore it
            continue;
        }else if(user_message[0] == '/'){

            /* ---------------------- */
            /* Process local commands */
            /* ---------------------- */

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

            /* ------------------------------------------ */
            /* Or fall through to send commands to server */
            /* ------------------------------------------ */
        }

        //Add a control character to the start of message so we know when it's
        //a new message since the message may be split up over multiple packets
        //message[0] = 0x02; //Start of text control character

        message_length = strlen(user_message);
            
        status = sendMessage(user_message, message_length + 1);
        if(status == -1){
            perror("Error");
        }

        wrefresh(chat_win);
        wrefresh(stdscr);

    }while(strcmp(user_message, "/q") && strcmp(user_message, "/quit") && strcmp(user_message, "/exit"));
  
    wprintw(chat_win, "\n -Leaving chat server-\n");
    wrefresh(chat_win); 
}

void printToChat(char * message, int bytes){
    
    //wprintw(chat_win, "\nReceived %d bytes", bytes);
    //wrefresh(chat_win);

    
    char *next;
    do{
        //wprintw(chat_win, "\n%d\n", bytes);
        if(message[0] == MESSAGE_START){
            wprintw(chat_win, "\n");
            printTime(); 
            message++; //Skip over message start character
        }
                
        wprintw(chat_win, "%s", message);

        message += strlen(message) + 1; //Move to next string - Add one to skip over the null character
        next = strchr(message, MESSAGE_START);
        if(next != NULL){
            next[0] = '\0';
            wprintw(chat_win, "%s", message);
            next[0] = MESSAGE_START;
            message = next;
        }else{
            break;
        }

    }while(1);
    

    /*int length = 0;
    while(bytes > 0){
        //wprintw(chat_win, "\n%d\n", bytes);
        if(message[0] == MESSAGE_START){
            wprintw(chat_win, "\n");
            printTime(); 
            message++;
            bytes--;
        }
        wprintw(chat_win, "%s", message);
        length = strlen(message); 
        message += length + 1; //Move to next string - Add one to skip over the null character
        if(length == bytes){
            bytes -= length; //Remaining bytes without a null character (the remainder is in another packet)
        }else{
            bytes -= length + 1; //Remaining bytes with a null character (the string is finished in this packet)
        }
    }*/

    wrefresh(chat_win); //Show message on chat window
    wrefresh(stdscr); //Ensures cursor in text window is show
}

void printTime(){
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

static void handler(int signum){
	pthread_exit(NULL);
}




/* Debugging method */
void *printMessage(){

    int i = 0;

    sleep(2); //Delay before starting to send messages
           
    while(1){

        sleep(1); //Delay between each message
        i++;
        wprintw(chat_win, "BobBot: For the #%d time, how are you?\n", i);
        wrefresh(chat_win);
        wrefresh(stdscr); //Ensures cursor in text window is show

    }
}