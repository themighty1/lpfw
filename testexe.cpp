#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h> //getpid()

using namespace std;

void sig_handler ( int signal ){
    exit(0);
}

int main(){
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = sig_handler;
    if ( sigaction ( SIGUSR1, &sa, NULL ) == -1 ){
      perror ( "sigaction" );
    }

    struct sockaddr_un addr;
    int fd;
    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
      }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ("/tmp/lpfwtest"+ to_string(getpid())).c_str(),
            sizeof(addr.sun_path)-1);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect error");
        exit(-1);
      }


    while(true){
        sleep(100);
    }
}
