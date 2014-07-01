#include <arpa/inet.h> //for ntohl()
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h> //for strerror()
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cassert>
#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>

#include "common/syscall_wrappers.h"
using namespace std;


string random_str = "empty";
int tcp_server_port = 0;
int udp_server_port = 0;
bool bLocalTCPServerStarted = false;
bool bLocalUDPServerStarted = false;
string iface_str; //contains my external interface IP
//forward declaration
int bind_tcp_client(bool bWrite);
void fork_setup();

bool fileExists(const string filename){
  struct stat buf;
  if (stat(filename.c_str(), &buf) != -1){return true;}
  return false;
}


void die2(string message){
  cout << message << "\n";
  cout << "in testprocess \n";
  exit(1);
}


//split on a delimiter and return chunks
vector<string> split_string(string arg, string delimiter = " "){
  vector<string> output;
  int pos = 0;
  string token;
  while (true){
    pos = arg.find(delimiter);
    if (pos == string::npos){ //last element
      token = arg.substr(0, arg.length());
      output.push_back(token);
      break;
    }
    token = arg.substr(0, pos);
    output.push_back(token);
    arg.erase(0, pos + 1);
  }
  return output;
}


//Create/(check existence of) lpfwtest group and add ourselves to it
//After that set this process's gid to lpfwtest group
void setgid_lpfwtest() {
  errno = 0;
  struct group *m_group;
  m_group = getgrnam("lpfwtest");
  if (errno != 0) { die2("getgrnam error"); }
  if (!m_group) { //group doesnt yet exist
    cout << "lpfwtest group does not exist, creating...\n";
    if (system("groupadd lpfwtest") == -1) { die2("error in system(groupadd)\n"); }
    //else call getgrnam again after group creation
    errno = 0;
    m_group = getgrnam("lpfwtest");
    if(!m_group) { die2("failed to create lpfwtest group"); }
  }
  if (setgid(m_group->gr_gid) == -1) { die2(strerror(errno)); }
}


//let testdriver know my socket's local port number
int write_port_file(int sockfd, string protocol){
  struct sockaddr_in sin;
  socklen_t addrlen = sizeof(sin);
  if(getsockname(sockfd, (struct sockaddr *)&sin, &addrlen) == 0 &&
    sin.sin_family == AF_INET && addrlen == sizeof(sin)) {
    int local_port = ntohs(sin.sin_port);
    string suffix = ".none";
    if (protocol == "TCP"){suffix = ".tcp";}
    else if (protocol == "UDP"){suffix = ".udp";}
    ofstream socket_file("/tmp/lpfwtest/" + random_str + suffix);
    socket_file << to_string(local_port);
    socket_file.close();
    ofstream portready("/tmp/lpfwtest/"+random_str+".port-file-is-ready");
    portready.close();
    return local_port;
  }
  else{ die2("testprocess: could not get my local port number"); }
}


//Try to connect to a server and optionally wait for the server
//to respond before returning. Not waiting for the server to respond
//can be usefull when testing offline
void connect_tcp(int sockfd, string host, string port_str, bool bWait = true, string perms = "NONE") {
  if (bWait){ //doing full tcp conn, at this point the conn from quicktcp might have been
    //shutdown. We must shutdown socket and get a new one. TODO this is a code mess for now.
    shutdown(sockfd, SHUT_RDWR);
    sockfd = bind_tcp_client(false);
  }

  struct sockaddr_in serv_addr;
  int port = stoi(port_str);

  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  if(inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr)<=0) {
      die2("testprocess: inet_pton() failed"); }

  fd_set myset;
  struct timeval tv;
  int timeout = 0;
  int valopt;
  socklen_t lon;
  bool connected = false;

  if (bWait) timeout = 5;
  tv.tv_sec = timeout;
  tv.tv_usec = 0;

  cout << "testprocess: connecting to server \n";
  int res = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  if ( (res != -1 && (errno != EINPROGRESS || errno != EALREADY)) && (res != 0) ) {
    //EINPROGRESS happens when *this* connect is now in progress
    //EALREADY can happen when a previous (NOT *this*) connect is still in progress
    //res == 0 on non-blocking socket happens if the socket was already connected
    //to the remote host
    cout << "Unexpected return value: " << res << " sockfd was: " << sockfd << "\n";
    fprintf(stderr, "The errno is  %d - %s\n", errno, strerror(errno));
    exit(1);
  }
  write_port_file(sockfd, "TCP");
  do {
    FD_ZERO(&myset);
    FD_SET(sockfd, &myset);
    res = 0;
    res = select(sockfd+1, NULL, &myset, NULL, &tv);
    if (res < 0 && errno != EINTR) {
       fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
       exit(1);
    }
    else if (res > 0) {
      // Socket selected for write
      lon = sizeof(int);
      if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon) < 0) {
        fprintf(stderr, "Error in getsockopt() %d - %s\n", errno, strerror(errno));
        exit(1);
      }
      // Check the value returned...
      if (valopt) {
        if (valopt == 110){ //TODO what's the name for this error code?
          //Connection timed out
          fprintf(stderr, "Timeout in select() via valopt - Cancelling!\n");
          break;
        }
        fprintf(stderr, "Error in delayed connection() %d - %s\n", valopt, strerror(valopt));
        exit(1);
      }
      //else successfully connected
      cout << "TCP connection established...\n";
      connected = true;
      ofstream f("/tmp/lpfwtest/"+random_str+".connected");
      f.close();
      break;
    }
    else {
      cout << "timeout for host " << host << "\n";
      fprintf(stderr, "Timeout in select() - Cancelling!\n");
      break;
    }
  } while (1);
  if (connected && (perms == "DENY_ALWAYS" || perms == "DENY_ONCE")){
    cout << "ERROR******************* DENY* rule was able to connect \n";
    abort();
  }
  else if (!connected && (perms == "ALLOW_ALWAYS" || perms == "ALLOW_ONCE")){
    cout << "ERROR******************* ALLOW* rule was unable to connect \n";
    abort();
  }
}


void connect_udp(int sockfd, string host, string port_str, bool bWait = true, string perms = "NONE"){
  struct sockaddr_in serv_addr;
  int port = stoi(port_str);
  int timeout = 0;
  if (bWait) timeout = 5;

  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  if(inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr)<=0) {
      die2("testprocess: inet_pton() failed"); }

  int res = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  if (res != 0){
    cout << "Unknown return value \n";
    abort();
  }
   //No traffic has been sent at this point. We need to send a dummy packet to trigger netfilter.
   unsigned char msg[48]={010,0,0,0,0,0,0,0,0};	// NTP packet
   int rv = send(sockfd, msg, sizeof(msg), 0);
   if (rv == -1){
     fprintf(stderr, "Error in send() %d - %s\n", errno, strerror(errno));
     exit(1);
   }
   if (!bWait){ return;} //we dont care about the response
   //else //we need to get some data from the server to know that we indeed connected
   char buf[1024];
   bool bResponded = false;
   for (int i=0; i < timeout; ++i){
     rv = recv(sockfd, buf, sizeof(buf), 0);
     if (rv > 0){
       bResponded = true;
       break;
     }
     else if (rv == -1 && errno != EAGAIN){
       fprintf(stderr, "Error in recv() %d - %s\n", errno, strerror(errno));
     }
     sleep(1);
   }
   if (bResponded && (perms == "DENY_ALWAYS" || perms == "DENY_ONCE")){
     cout << "ERROR******************* UDP DENY* rule was able to connect \n";
     abort();
   }
   else if (!bResponded && (perms == "ALLOW_ALWAYS" || perms == "ALLOW_ONCE")){
     cout << "ERROR******************* UDP ALLOW* rule was unable to connect \n";
     cout << "while connecting to: " << host << "\n";
     abort();
   }
   else if (bResponded){
     cout << "UDP got data from server...\n";
     ofstream signal_file("/tmp/lpfwtest/"+random_str+".connected");
     signal_file.close();
   }
   //shutdown(sockfd, SHUT_RDWR);
}


void *thread_tcp_server (void *ptr){
  int list_s;                /*  listening socket          */
  struct sockaddr_in servaddr;  /*  socket address structure  */

  if ( (list_s = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
    fprintf(stderr, "ECHOSERV: Error creating listening socket.\n");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family      = AF_INET;
  string host = iface_str;
  if(inet_pton(AF_INET, host.c_str(), &servaddr.sin_addr)<=0) {
      die2("testprocess: error inet_pton() failed"); }

  servaddr.sin_port = htons(0);
  if ( bind(list_s, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 ) {
     fprintf(stderr, "bind error is  %d - %s\n", errno, strerror(errno));
  }
  tcp_server_port = write_port_file(list_s, "TCP");
  //we need to add an iptables rule for this specific INPUT port
  _system (string("iptables -A INPUT -p tcp --dport " + to_string(tcp_server_port) +
                  " -m state --state NEW -j NFQUEUE --queue-num 11221").c_str());

  if ( listen(list_s, 500) < 0 ) {
    fprintf(stderr, "ECHOSERV: Error calling listen()\n");
    exit(EXIT_FAILURE);
  }
  cout << "TCPserver listening on port " <<  tcp_server_port << "\n";
  bLocalTCPServerStarted = true;

  if ( (accept(list_s, NULL, NULL) ) < 0 ) {
        fprintf(stderr, "ECHOSERV: Error calling accept()\n");
        exit(EXIT_FAILURE);
  }
  //we get here when server accept()ed the connection
  cout << "TCP server accepted connection...\n";
  //just create the file to let the testdriver know that we connected OK
  ofstream signal_file("/tmp/lpfwtest/" + random_str + ".connected");
  signal_file.close();
}


void *thread_udp_server (void *ptr){
  int list_s;                /*  listening socket          */
  struct sockaddr_in servaddr;  /*  socket address structure  */

  if ( (list_s = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    fprintf(stderr, "ECHOSERV: Error creating listening socket.\n");
    abort();
  }
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family      = AF_INET;
  string host = iface_str;
  if(inet_pton(AF_INET, host.c_str(), &servaddr.sin_addr)<=0) {
      die2("testprocess: inet_pton() failed"); }

  servaddr.sin_port = htons(0);
  if ( bind(list_s, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 ) {
     fprintf(stderr, "ECHOSERV: Error calling bind()\n");
     abort();
  }
  udp_server_port = write_port_file(list_s, "UDP");
  _system (string("iptables -A INPUT -p udp --dport " + to_string(udp_server_port) +
                  " -m state --state NEW -j NFQUEUE --queue-num 11221").c_str());

  cout << "UDPserver listening on port " << udp_server_port << "\n";
  bLocalUDPServerStarted = true;
  char msg[1000];
  int n = recv(list_s, msg, 1000, 0); //block until data

  cout << "UDP server received data on port " << udp_server_port << "\n";
  //let the testdriver know that we were connected to
  ofstream signal_file("/tmp/lpfwtest/" + random_str + ".connected");
  signal_file.close();
}




void localtcpserver(){
  pthread_t thr_tcpserver;
  pthread_create(&thr_tcpserver ,(pthread_attr_t*)NULL, thread_tcp_server, (void *)NULL);
}

void localudpserver(){
  pthread_t thr_udpserver;
  pthread_create(&thr_udpserver ,(pthread_attr_t*)NULL, thread_udp_server, (void *)NULL);
}


//send a UDP packet to a local UDP server. This function doesn't wait for the response
//because we are testing the UDP server. The UDP server will register whether the conn
//to it succeeded
void localudpsend(){
  //send a packet (i.e. connect to the server)
  struct sockaddr_in serv_addr;
  int sockfd = 0;
  int timeout = 0;
  string host = iface_str;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM , 0)) < 0) {
      die2("testprocess: socket() error"); }
  long arg;
  if ((arg = fcntl(sockfd, F_GETFL, NULL)) == -1){
    die2("testprocess: fcntl() error");
  }
  arg |= O_NONBLOCK;
  if (fcntl(sockfd, F_SETFL, arg) == -1){
    die2("testprocess: fcntl() error");
  }
  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;

  while (!bLocalUDPServerStarted){} //spin. hopefully < 1 second
  serv_addr.sin_port = htons(udp_server_port);
  if(inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr)<=0) {
      die2("testprocess: inet_pton() error"); }

  int res = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  if (res != 0){
    cout << "Unknown return value:" << res << "\n";
    fprintf(stderr, "Error in connect() %d - %s\n", errno, strerror(errno));
    abort();
  }
   //No traffic has been sent at this point. We need to send a dummy packet to trigger netfilter.
   unsigned char msg[48]={010,0,0,0,0,0,0,0,0};	// NTP packet
   int rv = send(sockfd, msg, sizeof(msg), 0);
   if (rv == -1){
     fprintf(stderr, "Error in send() %d - %s\n", errno, strerror(errno));
     exit(1);
   }
   //Can shutdown the socket because the packet is on the way to the server.
   //Unline TCP, we dont have to wait for the handshake to complete.
   //shutdown(sockfd, SHUT_RDWR);
}


void localtcpsend(){
  //send a packet (i.e. connect to the server)
  struct sockaddr_in serv_addr;
  int sockfd = 0;
  string host = iface_str;

  if ((sockfd = socket(AF_INET, SOCK_STREAM , 0)) < 0) {
      die2("testprocess: socket() failed"); }
  long arg = fcntl(sockfd, F_GETFL, NULL);
  arg |= O_NONBLOCK;
  fcntl(sockfd, F_SETFL, arg);
  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;

  while (!bLocalTCPServerStarted){} //spin. hopefully < 1 second
  serv_addr.sin_port = htons(tcp_server_port);
  if(inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr)<=0) {
      die2("testprocess: inet_pton() failed"); }

  fd_set myset;
  struct timeval tv;
  int timeout = 0;
  int valopt;
  socklen_t lon;

  tv.tv_sec = timeout;
  tv.tv_usec = 0;

  cout << "connecting to local server on port " << tcp_server_port << "\n";
  int res = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  if ( !(res == -1 && errno == EINPROGRESS) ) {
    //res==0 is an error b/c it cant happen on connect() with non-blocking socket
    cout << "Unexpected return value: " << res << "\n";
    fprintf(stderr, "The errno is  %d - %s\n", errno, strerror(errno));
    exit(1);
  }
  cout << "selecting \n";
  do {
    FD_ZERO(&myset);
    FD_SET(sockfd, &myset);
    res = select(sockfd+1, NULL, &myset, NULL, &tv);
    if (res < 0 && errno != EINTR) {
       fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
       exit(1);
    }
    else if (res > 0) {
      // Socket selected for write
      lon = sizeof(int);
      if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon) < 0) {
        fprintf(stderr, "Error in getsockopt() %d - %s\n", errno, strerror(errno));
        exit(1);
      }
      // Check the value returned...
      if (valopt) {
          fprintf(stderr, "Error in delayed connection() %d - %s\n", valopt, strerror(valopt));
          exit(1);
      }
      //else successfully connected
      cout << "local TCP connection established...\n";
      //just create the file to let the testdriver know that we connected OK
      ofstream f("/tmp/lpfwtest/"+random_str+".connected");
      f.close();
      break;
    }
    else {
      fprintf(stderr, "Timeout in select() - Cancelling!\n");
      break;
    }
  } while (1);

  //whether we connected or not will be signalled by the server itself
  //we need to immediately close the socket, otherwise it may retry connection
  //and mess up the testing logic

  //TODO if we shutdown the socket immediately then the TCP handshake will be interrupted
  //if we do not shutdown it, we gonna leak it. Find a workaround.
  //shutdown(sockfd, SHUT_RDWR);
}

//wait for timeout seconds for the file to appear on filesystem
void wait_for_semaphore_file(string path, int timeout=7){
  struct timespec refresh_timer;
  refresh_timer.tv_sec=0;
  refresh_timer.tv_nsec=1000000000/100;
  int loops = 0;
  while (true) {
    fstream f(path);
    if (f.good()){
      f.close();
      return;
    }
    f.close();
    //else file does not yet exist
    ++loops;
    if (loops > timeout*100){ //timeout after 7 seconds
      cout << "Timeout waiting on the semaphore file " << path << "\n";
      exit(1);
    }
    while(nanosleep(&refresh_timer, &refresh_timer));
  }
}


//Only bind to a local port and dont send anything yet
//Because we have to report the local port to frontend, so it knows
//from which port to expect a new request
int bind_tcp_client(bool bWrite = true){
  struct sockaddr_in sa_loc;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) { die2("testprocess: socket() failed"); }
  long arg = fcntl(fd, F_GETFL, NULL);
  arg |= O_NONBLOCK;
  fcntl(fd, F_SETFL, arg);
  memset(&sa_loc, 0, sizeof(struct sockaddr_in));
  sa_loc.sin_family = AF_INET;
  //no need to expilictely set local address, otherwise I got errors on connect()
  sa_loc.sin_port = htons(0); //kernel chooses a free port
  if ( bind(fd, (struct sockaddr *)&sa_loc, sizeof(struct sockaddr_in)) < 0){
        fprintf(stderr, "Error calling bind()\n");
        fprintf(stderr, "The errno is  %d - %s\n", errno, strerror(errno));
        exit(1);
  }
  if (bWrite){
    write_port_file(fd, "TCP");
  }
  return fd;
}


//Only bind to a local port and dont send anything yet
//Because we have to report the local port to frontend, so it knows
//from which port to expect a new request
int bind_udp_client(bool bWrite = true){
  struct sockaddr_in sa_loc;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) { die2("testprocess: udp socket() failed"); }
  long arg = fcntl(fd, F_GETFL, NULL);
  arg |= O_NONBLOCK;
  fcntl(fd, F_SETFL, arg);
  memset(&sa_loc, 0, sizeof(struct sockaddr_in));
  sa_loc.sin_family = AF_INET;
  //no need to expilictely set local address, otherwise I got errors on connect()
  sa_loc.sin_port = htons(0); //kernel chooses a free port
  if ( bind(fd, (struct sockaddr *)&sa_loc, sizeof(struct sockaddr_in)) < 0){
        fprintf(stderr, "Error calling bind()\n");
        fprintf(stderr, "The errno is  %d - %s\n", errno, strerror(errno));
        exit(1);
  }
  if (bWrite){
    write_port_file(fd, "UDP");
  }
  return fd;
}


void flood_tcp(){
  int sock_num = 10;
  vector<int> open_sockets;
  for (int i=0; i<sock_num; ++i){
    int newsock = bind_tcp_client(false);
    open_sockets.push_back(newsock);
  }
  cout << "****FLOOD finished creating flood sockets\n";
  for (int j=0; j<sock_num; ++j){
    //connect_tcp(open_sockets[j], false); //TODO change func sig
  }
  cout << "****FLOOD finished connecting flood sockets\n";
  sleep(1);
  for (int k=0; k<sock_num; ++k){
    shutdown(open_sockets[k], SHUT_RDWR);
  }
  cout << "****FLOOD finished shutting down flood sockets\n";
}


void command_loop(){
  struct timespec refresh_timer;
  refresh_timer.tv_sec=0;
  refresh_timer.tv_nsec=1000000000/100;

  int bound_socket = 0;
  while (true){
    assert(!fileExists("/tmp/lpfwtest/"+random_str+".ready-to-receive-commands"));
    ofstream ready4comm("/tmp/lpfwtest/"+random_str+".ready-to-receive-commands");
    ready4comm.close();
    //wait for a command to arrive
    while (true) {
      if (! fileExists("/tmp/lpfwtest/" + random_str + ".command-file-is-ready")){
        while(nanosleep(&refresh_timer, &refresh_timer));
      }
      else {
        remove(string("/tmp/lpfwtest/" + random_str + ".command-file-is-ready").c_str());
        break;
      }
    }
    //read the actual command
    string comm_str;
    ifstream command("/tmp/lpfwtest/" + random_str + ".command");
    getline(command, comm_str);
    command.close();
    assert (comm_str != "");
    vector<string> args = split_string(comm_str);
    for (int i=0; i<args.size(); ++i){
      if (args[i] == "tcp") {
        cout << "testprocess: doing tcp \n";
        connect_tcp(bound_socket, args[i+1], args[i+2], true, args[i+3]);
        i += 3;
      }
      else if (args[i] == "udp") {
        cout << "testprocess: doing udp \n";
        connect_udp(bound_socket, args[i+1], args[i+2], true, args[i+3]);
        i += 3;
      }
      else if (args[i] == "quicktcp") {
        cout << "testprocess: doing quicktcp \n";
        connect_tcp(bound_socket, args[i+1], args[i+2], false);
        i += 2;
      }
      else if (args[i] == "quickudp") {
        cout << "testprocess: doing quickudp \n";
        connect_udp(bound_socket, args[i+1], args[i+2], false);
        i += 2;
      }
      else if (args[i] == "client") {
        cout << "testprocess: acting as client \n";
        setgid_lpfwtest();
      }
      else if (args[i] == "bind_tcp_client") {
        cout << "testprocess: doing bind_tcp_client \n";
        bound_socket = bind_tcp_client();
      }
      else if (args[i] == "bind_udp_client") {
        cout << "testprocess: doing bind_udp_client \n";
        bound_socket = bind_udp_client();
      }
      else if (args[i] == "flood_tcp") {
        cout << "testprocess: doing tcp_flood \n";
        flood_tcp();
      }
      else if (args[i] == "localtcpserver") {
        cout << "testprocess: doing localtcpserver \n";
        localtcpserver();
      }
      else if (args[i] == "localudpserver") {
        cout << "testprocess: doing localudpserver \n";
        localudpserver();
      }
      else if (args[i] == "localtcpquicksend") {
        cout << "testprocess: doing localtcpquicksend \n";
        localtcpsend();
      }
      else if (args[i] == "localudpquicksend") {
        cout << "testprocess: doing localudpquicksend \n";
        localudpsend();
      }
      else if (args[i] == "localtcpconnect") {
        cout << "testprocess: doing localtcpconnect \n";
        localtcpsend();
      }
      else if (args[i] == "localudpconnect") {
        cout << "testprocess: doing localudpconnect \n";
        localudpsend();
      }
      else if (args[i] == "terminate") {
        cout << "testprocess: doing terminate \n";
        ofstream f("/tmp/lpfwtest/"+random_str+".terminated");
        f.close();
        exit(0);
      }
      else if (args[i] == "fork") {
        cout << "testprocess: doing fork \n";
        pid_t pID = fork();
        if (pID < 0) {cout << "Error: Failed to fork"; abort();}
        else if (pID == 0 ) { //in child
          fork_setup();
        }
        else {continue;} //in parent
      }
    }
  }
}



void fork_setup(){
  //inherit parent's randID + ".fork"
  random_str = random_str+".fork";
  cout << "in fork changed randomstr to: " << random_str << "\n";
  //write own pid into file
  ofstream pidfile("/tmp/lpfwtest/"+random_str+".pid");
  pidfile << to_string((int)getpid());
  pidfile.close();
  ofstream ff("/tmp/lpfwtest/"+random_str+".pid-file-is-ready");
  ff.close();

  command_loop();
}


int main(int argc, const char* argv[]){
  cout << "In testprocess \n";
  ifstream ifacefile("/tmp/lpfwtestinterface");
  if (! ifacefile.is_open()) {
      cout << "Could not find /tmp/lpfwtestinterface file \n";
      cout << "This file should contain your network interface IP, e.g. 109.110.9.42 \n";
      exit(1);
  }
  getline(ifacefile, iface_str);
  ifacefile.close();

  random_str = argv[1]; //the calling process passes a random string
  //our full path is "/tmp/lpfwtest/testprocess" + random
  //for some reason I couldnt extract own name from argv[0]
  assert (random_str != "");
  //write own pid into file
  ofstream pidfile("/tmp/lpfwtest/"+random_str+".pid");
  pidfile << to_string((int)getpid());
  pidfile.close();
  ofstream ff("/tmp/lpfwtest/"+random_str+".pid-file-is-ready");
  ff.close();

  command_loop();
}






