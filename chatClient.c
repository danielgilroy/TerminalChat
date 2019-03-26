#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <pthread.h>
#include <signal.h>
#include <ncurses.h>

#include "tcpClient.h"

void initializeChat();
void initializeConnection();
void terminateChat();
void terminateChatNow();
void *incomingMessages();
void outgoingMessages();
void printToChat(char *);
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
    int status;
    char response[256];

    status = joinServer(response);

    if (status < 0){
        wprintw(chat_win, " -There was an error connecting to the server-\n");
        wprintw(chat_win, "    -The chat client will close shortly-\n");
        wrefresh(chat_win);
        terminateChat();
    }

    printToChat(response);
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

    int status;
    char server_message[256];
     
    while(1){

        status = receiveMessage(server_message, sizeof(server_message));
    
        if(status <= 0){
            wprintw(chat_win, "\n    -The chat server has shutdown-\n");
            wprintw(chat_win, " -The chat client will close shortly-\n");
            wrefresh(chat_win);
            terminateChatNow();  
        }

        /* Debug print */
        //wprintw(chat_win, "Received %d characters\n", status);
        /* ----------- */

        printToChat(server_message);
    }

}

void outgoingMessages(){

    int status;
    char user_message[256];
    int message_length;

    do{

        //Get input string from the user
        getnstr(user_message, COLS - 10);

        //Move cursor to starting position and clear the line
        wmove(stdscr, LINES-1, 6);
        clrtoeol();
        wrefresh(chat_win);
        wrefresh(stdscr);

        if(user_message[0] == '\0'){
            //Message is blank so ignore it
            continue;
        }else if(user_message[0] == '/'){

            //Process local command or send command to server

            //Local command - Clear chat window
            if(strcmp(user_message, "/clear") == 0){
                werase(chat_win);
            }

        }else{

            /* Debug Local Print */
            //wprintw(chat_win, "You: %s\n", user_message);
            //wrefresh(chat_win); 
            /* End Debug */

            message_length = strlen(user_message);
            
            //Append carriage return and line feed to match telnet standard
            //user_message[message_length] = '\r';
            //user_message[++message_length] = '\n';

            status = sendMessage(user_message, message_length + 1);
            if(status == -1){
                perror("Error");
            }

        }

        //Refresh windows
        wrefresh(chat_win);
        wrefresh(stdscr);

    }while(strcmp(user_message, "/exit"));
  
    wprintw(chat_win, "\n -Leaving chat server-\n");
    wrefresh(chat_win); 

}

void printToChat(char * message){

    printTime();
    wprintw(chat_win, "%s\n", message);
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

    sleep(2);
           
    while(1){

        sleep(1);
        i++;
        wprintw(chat_win, "BobBot: For the #%d time, how are you?\n", i);
        wrefresh(chat_win);
        wrefresh(stdscr); //Ensures cursor in text window is show

    }

}

