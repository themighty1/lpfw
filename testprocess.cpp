#include <arpa/inet.h> //for ntohl()
#include <grp.h>
#include <iostream>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <string>
#include <string.h> //for strerror()
#include <linux/netfilter.h> //for NF_ACCEPT, NF_DROP etc. This sucker has to go to the bottom,
//otherwise you'll get compile errors

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <cassert>

#include "common/syscall_wrappers.h"
using namespace std;


void die(string message){
  cout << message;
  exit(1);
}


//Create/(check existence of) lpfwtest group and add ourselves to it
//After that set this process's gid to lpfwtest group
void setgid_lpfwtest() {
  errno = 0;
  struct group *m_group;
  m_group = getgrnam("lpfwtest");
  if (errno != 0) { die("getgrnam error"); }
  if (!m_group) { //group doesnt yet exist
    cout << "lpfwtest group does not exist, creating...\n";
    if (system("groupadd lpfwtest") == -1) { die("error in system(groupadd)\n"); }
    //else call getgrnam again after group creation
    errno = 0;
    m_group = getgrnam("lpfwtest");
    if(!m_group) { die("failed to create lpfwtest group"); }
  }
  if (setgid(m_group->gr_gid) == -1) { die(strerror(errno)); }
}


void connect_to_server(){
  int sockfd = 0;
  struct sockaddr_in serv_addr;
  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) { die("socket() failed"); }
  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(80);
  if(inet_pton(AF_INET, "173.194.78.101", &serv_addr.sin_addr)<=0) { die("inet_pton() failed"); }
  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { die("testprocess: connect() failed"); }
  printf("Connection established...\n");
  sleep(100);
}

int main(){
  //setgid on our own process
  setgid_lpfwtest();
  //try to send some data and see if queue handler triggers
  connect_to_server();
}


