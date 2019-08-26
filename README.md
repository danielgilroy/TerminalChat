
# Description

Linux terminal chat server and client that were programmed in C and make use of C socket programming (TCP protocol), pthreads, ncurses, libsodium, and SQLite3. The project compiles into two executables "chatserver" and "chatclient" which are used for hosting the chat server and connecting to the chat server respectively.

- Multiple chat rooms, direct messaging, username registration, account types, spam filtering, and user kicking
- Utilizes C socket programming (TCP protocol) to make connections and send/recveive messages
- Handles multiple messages in one packet and incomplete message split up over multiple packets
- Server-side storage of usernames and libsodium-hashed passwords within a local SQLite3 database  
- Client application uses ncurses to display separate text areas for incoming chat text and outgoing user input
- Custom user-input echoing with password protection and last message sent history recall

# Table of Contents

- [Description](#description)
- [Libraries Used](#libraries-used)
- [Building](#building)
- [Application Usage](#application-usage)
- [Private Messaging](#private-messaging)
- [Commands](#commands)

# Libraries Used

The following libraries were used and will be required to run the chat server and chat client.

Installation instructions are provided for your convenience. The displayed versions are the latest versions tested.

>## [ncurses](https://www.gnu.org/software/ncurses/) v6.1

    sudo apt-get update
    sudo apt-get install libncurses5-dev libncursesw5-dev

>## [uthash](https://troydhanson.github.io/uthash/) v2.1.0

    sudo apt-get update
    sudo apt-get install uthash-dev

>## [SQLite](https://www.sqlite.org/index.html) v3.22.0

    sudo apt-get update
    sudo apt-get install sqlite3 libsqlite3-dev

>## [Libsodium](https://libsodium.gitbook.io/doc/) v1.0.18

Download a [tarball of libsodium](https://download.libsodium.org/libsodium/releases/), preferably the latest stable version, then perform the following:

    ./configure
    make && make check
    sudo make install

# Building

This application was developed for Linux and makes use of pthreads. Therefore, Windows is not natively supported due to the lack of pthreads on Windows operating systems. For use on Windows, you can use the Windows Subsystem for Linux (WSL) or Cygwin.

- Developed on Ubuntu v18.04.2 LTS

- Compiled with GCC v7.4.0

To build the chatserver and chatclient applications, install the [required libraries mentioned above](#libraries-used) and then perform the compilation by running the Makefile in the root directory.

    make

If for some reason you only want to compile one of the applications, you can run the application-specific Makefile located in each of the subdirectories.

# Application Usage

>## Chat Server

The chat server can be launched without any arguments, which will result in the default port number being used, or one can be manually specified. If either the default port or the user-specified port is already in use, the server will automatically find an unused port to use and display it on the terminal.

    ./chatserver
    ./chatserver <port_number>

The first time the chat server is launched, a main-admin acount with the username "*admin*" will be created. Simply enter the desired password twice and it will register the admin account in the local database. The local database is stored as a SQLite database named "*users.db*" and can be deleted at anytime to clear all the registered usernames and passwords.

>## Chat Client

The chat client can be launched without any arguments, which will result in the default IP address and port number being used, or they can be manually specified by the user.

    ./chatclient
    ./chatclient <IP_address> <port_number>
    ./chatclient <IP_address>
    ./chatclient <port_number>

# Private Messaging

>## @

Private messages can be sent to users by inserting the '@' symbol before their username. Note that private messaging works across the whole server so it doesn't matter if the two users are in the same chat room or not. When a user receives a private message, the senders username will be followed by ">>" to let the user know it's a private message.

    @<username> <private_message>

# Commands

The following commands are entered in the chat client once connected to the chat server

>## clear

The "*clear*" command is used to clear the scren to a blank state.

    /clear

>## color

The "*color*" command enables colors for the chat client window. You can use the command without arguments to toggle between modes or specify "*on*" / "*off*" as an argument. The British English spelling "*colour*" is also supported.

    /color
    /colour
    /color <on/off>
    /colour <on/off>

>## join

The "*join*" command is used to join the specified chat room. Enter the desired room number as an argument to join that room.

    /join <room_number>

>## nick

The "*nick*" command is used to change your nickname. If no argument is given, then the server will echo back your own username. If the specified nickname has been previously registered, then the password for that nickname must be entered before you can use it.

    /nick
    /nick <username>
    /nick <username> <password>

>## register

The "*register*" command allows you to register a username so only you have access to it. Enter your desired username and repeat the password twice. If a username is already registered, an error is returned.

    /register <username> <password> <password>

>## unregister

The "*unregister*" command is used to unregister a username that is no longer needed. Enter the username and password as arguments for the username you wish to unregister. Admin account types are not required to enter a password which gives admins full control over the registered usernames.

    /unregister <username> <password>
    /unregister <username>

>## whois

The "*whois*" command displays the ip and port information about a user. If no argument is given, it will display information about yourself. If a username argument is given, it will return information about the specified user. Note that only admins can get information about other users.

    /whois
    /whois <username>

>## who

The "*who*" command displays the current users on the server. If no argument is given, then a list of all users in every chat room will be printed to the screen. If a room number is given, then only the users in the specified chat room will be displayed.

    /who
    /who <room_number>

>## where

The "*where*" command is used to display which chat room the specified user is currently in. If no argument is given, then the room you are currently in will be displayed.

    /where
    /where <username>

>## kick

The "*kick*" command is used to kick the specified user from the chat server: Note that only admins can use this command.

    /kick <username>

>## admin

The "*admin*" command is used to toggle the user type of the specified user between a regular user and an admin user. Note that only the main-admin account with the username "*admin*" can change user types. The main-admin account is created the first time the server is started.

    /admin <username>

>## die

The "*die*" command is used to send a shutdown signal to the server. Note that only admins can use this command.

    /die
