#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <string>
#include <string.h> //memset()
#include <unistd.h> //getpid()
#include "unix_socket.h"

using namespace std;

void sig_handler ( int signal ){
    exit(0);
}

int main(int argc, char* argv[]){
    cout << "in testexe arg count is " << argc << endl;
    for (int i=0; i < argc; i++){
        cout << argv[i] << endl;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = sig_handler;
    if ( sigaction ( SIGUSR1, &sa, NULL ) == -1 ){
      perror ( "sigaction" );
    }

    //fork if needed, wait for the forked() child to get ready
    if (argc == 1){
        cout << "in testexe forking" << endl;
        pid_t child_pid = fork();
        if (child_pid == 0){
            //inherits sighandler from parent
            unix_socket_connect("/tmp/lpfwtest" + to_string(getpid()));
            while (true) sleep (100);
        }
        //wait for child to start
        unix_socket_block("/tmp/lpfwtest" + to_string(child_pid));
        //write child's PID into a file
        ofstream f;
        f.open("/tmp/lpfwtest." + to_string(getpid()) + ".child");
        f << to_string(child_pid);
        f.close();
    }

    cout << "testexe connecting to unix socket" << endl;
    unix_socket_connect("/tmp/lpfwtest"+ to_string(getpid()));

    while(true){
        sleep(100);
    }
}
