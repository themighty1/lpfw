#include "unix_socket.h"
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h> //for unlink()

void unix_socket_block(string name){
    //when child starts it connects to a unix socket
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, name.c_str(), sizeof(addr.sun_path)-1);
    unlink(name.c_str());
    int fd, cl;
    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind error");
        exit(-1);
    }
    if (listen(fd, 5) == -1) {
        perror("listen error");
        exit(-1);
    }
    //will block here until accept()
    if ( (cl = accept(fd, NULL, NULL)) == -1) {
     perror("accept error");
     exit(-1);
   }
}

void unix_socket_connect(string name){
    struct sockaddr_un addr;
    int fd;
    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
      }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, name.c_str(),
            sizeof(addr.sun_path)-1);
    //it may be possible that the fork()ed child
    //is trying to connect() faster than the parent could
    //create the socket. That's why we retry a few times
    while (true){
        int i = 0;
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
            perror("connect error");
            if (i++ == 10) exit(1);
            continue;
          }
        else {
            break;
        }
    }
}
