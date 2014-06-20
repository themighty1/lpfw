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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <vector>
#include <errno.h>
#include <cassert>

//otherwise you'll get compile errors
#include "common/includes.h"
#include "common/syscall_wrappers.h"
using namespace std;

extern vector<string> split_string(string input);


typedef struct {
    int qfd;
    struct nfq_handle *handle;
} thread_args;


void die_msg (string message) {
  cout << message;
  exit(1);
}


void* thread_nfq (void *passed_args) {
  thread_args args = *(thread_args*)passed_args;
  free(passed_args);
  //endless loop of receiving packets and calling a handler on each packet
  int rv;
  char buf[4096] __attribute__ ( ( aligned ) );
  while ( ( rv = recv ( args.qfd, buf, sizeof ( buf ), 0 ) ) && rv >= 0 ){
    nfq_handle_packet ( args.handle, buf, rv );
  }
}


int handle_packet ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfad, void *mdata ) {
  struct iphdr *ip;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
  if ( !ph ) { die_msg ("ph == NULL, should never happen, please report"); }
  u_int32_t id = ntohl ( ph->packet_id );
  nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );
  char daddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
  int verdict;
  u_int16_t sport_netbyteorder, dport_netbyteorder;
  string path,pid;
  unsigned long long starttime;
  int nfmark;
  cout << "nfq processed packet with destination" << daddr << "\n";
  nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
}


void init_nfq_handler()
{
  struct nfq_handle *handle = _nfq_open();
  _nfq_unbind_pf (handle, AF_INET );
  _nfq_bind_pf (handle, AF_INET );
  struct nfq_q_handle *q_handle = _nfq_create_queue (handle, 22222, &handle_packet, (void*)NULL );
  //copy only 40 bytes of packet to userspace - just to extract tcp source field
  _nfq_set_mode (q_handle, NFQNL_COPY_PACKET, 40 );
  _nfq_set_queue_maxlen (q_handle, 200 );
  int qfd = nfq_fd (handle);
  cout << "nfq registered" << "\n";
  pthread_t thr_nfq;
  thread_args *args = (thread_args*)malloc(sizeof(thread_args));
  args->handle = handle;
  args->qfd = qfd;
  _pthread_create ( &thr_nfq , (pthread_attr_t*)NULL, thread_nfq, args);
}


void* thread_newprocess (void *arg) {
  string commline((char *)arg);
  free(arg);
  _system(commline.c_str());
}


void start_process(string commline){
  pthread_t thr_newprocess;
  char *arg = (char *)malloc(strlen(commline.c_str()));
  strncpy(arg, commline.c_str(), strlen(commline.c_str()));
  _pthread_create (&thr_newprocess, (pthread_attr_t*)NULL, thread_newprocess, arg);
}


void* start_frontend_thread(void *port_ptr){
  int portno = *(int *)port_ptr;
  free(port_ptr);
  int sockfd, n;
  char buffer[256];
  struct sockaddr_in serv_addr;
  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) { die_msg("socket() failed"); }
  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) { die_msg("inet_pton() failed"); }
  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { die_msg("connect() failed"); }

  while (true){
    bzero(buffer,256);
    n = read(sockfd,buffer,255);
    if (n < 0) {//no data
      sleep(1);
      continue;
    }
    cout << "frontend received:" << buffer << "\n";
    string data(buffer);
    vector<string> data_parts = split_string(data);
    if (data_parts[0]=="REQUEST" && data_parts[1]=="/tmp/testprocess1"){
      string path = data_parts[1];
      string pid = data_parts[2];
      string response = "ADD " + path + " " + pid + " " + "ALLOW_ALWAYS";
      if (send(sockfd, response.c_str(), response.length(), MSG_NOSIGNAL) < 0) {
        cout << "ERROR writing to socket";
        _close(sockfd);
        return;
      }
    }
    else {
      cout << "wrong request received: " << data << "\n";
    }
  }
}


void* thread_test ( void *port_ptr ) {
  pthread_t thr_frontend;
  _pthread_create(&thr_frontend ,(pthread_attr_t*)NULL, start_frontend_thread, (void *)port_ptr);
  char *temppath = get_current_dir_name();
  string cwd(temppath);
  free(temppath);

  string cp_cmd = "cp " + cwd + "/testprocess /tmp/testprocess1";
  _system(cp_cmd.c_str());
  start_process("/tmp/testprocess1");

  while (true) {
    sleep(1);
  }


}
