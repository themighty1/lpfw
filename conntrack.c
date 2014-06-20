#include <errno.h>
#include <fstream>
#include <iostream>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <netinet/in.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h> //for memcpy
#include <pthread.h>
#include <queue>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>       /* time */
#include <unistd.h>
#include <vector>

#include "conntrack.h"
#include "lpfw.h"
#include "common/includes.h"
#include "common/syscall_wrappers.h"

using namespace std;

queue<string> ctmsgQueue;

pthread_t tcp_export_thr;
//ct_delete_mark_thread uses waiting on condition
pthread_cond_t condvar = PTHREAD_COND_INITIALIZER;
pthread_mutex_t condvar_mutex = PTHREAD_MUTEX_INITIALIZER;
char predicate = FALSE;
//two NFCT_Q_DUMP simultaneous operations can produce an error
pthread_mutex_t ct_dump_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ct_entries_mutex = PTHREAD_MUTEX_INITIALIZER;

//netfilter mark to be put on an ALLOWed packet
int nfmark_to_set_out_tcp, nfmark_to_set_out_udp,nfmark_to_set_out_icmp, nfmark_to_set_in;
int nfmark_to_delete_in, nfmark_to_delete_out;

struct nf_conntrack *ct_out_tcp, *ct_out_udp, *ct_out_icmp, *ct_in;
struct nfct_handle *dummy_handle_delete, *dummy_handle_setmark_out, *dummy_handle_setmark_in;
struct nfct_handle *setmark_handle_out_tcp, *setmark_handle_in, *setmark_handle_out_udp, *setmark_handle_out_icmp;

//this array is used internally by lpfw to prepare for export
ulong ct_array[CT_ENTRIES_EXPORT_MAX][9] = {};
//this array is built for export to frontend based on ct_array
ulong ct_array_export[CT_ENTRIES_EXPORT_MAX][5] = {};
/*
  [0] nfmark (export[0])
  [1] bytes in allowed
  [2] bytes out allowed
  [3] bytes in from all previously destroyed conntracks which had this nfmark
  [4] bytes out from all previously destroyed conntracks which had this nfmark
  [5] [1] + [3] (export[1])
  [6] [2] + [4] (export[2])
  [7] total bytes in denied so far  (export[3])
  [8] total bytes out denied so far (export[4])
*/


void * thread_ct_destroy( void *ptr)
{
  struct nfct_handle *traffic_handle;
  if ((traffic_handle = nfct_open(NFNL_SUBSYS_CTNETLINK, NF_NETLINK_CONNTRACK_DESTROY)) == NULL)
    {
      perror("nfct_open");
    }
  if ((nfct_callback_register(traffic_handle, NFCT_T_ALL, ct_destroy_cb, NULL) == -1))
    {
      perror("cb_reg");
    }
  int res = 0;
  res = nfct_catch(traffic_handle); //the thread should block here
}

void* thread_ct_delete_mark ( void* ptr )
{
  u_int8_t family = AF_INET; //used by conntrack
  struct nfct_handle *deletemark_handle;
  if ((deletemark_handle = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if ((nfct_callback_register(deletemark_handle, NFCT_T_ALL, ct_delete_mark_cb, NULL) == -1))
    {
      perror("cb_reg");
    }

  while(1)
    {
      _pthread_mutex_lock(&condvar_mutex);
      while(predicate == FALSE)
	{
	  pthread_cond_wait(&condvar, &condvar_mutex);
	}
      predicate = FALSE;
      _pthread_mutex_unlock(&condvar_mutex);
      _pthread_mutex_lock(&ct_dump_mutex);
      if (nfct_query(deletemark_handle, NFCT_Q_DUMP, &family) == -1)
	{
	  perror("query-DELETE");
	}
      _pthread_mutex_unlock(&ct_dump_mutex);
    }
}

int setmark_out_tcp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  nfct_set_attr_u32(mct, ATTR_MARK, nfmark_to_set_out_tcp);
  nfct_query(dummy_handle_setmark_out, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}

int setmark_out_udp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  nfct_set_attr_u32(mct, ATTR_MARK, nfmark_to_set_out_udp);
  nfct_query(dummy_handle_setmark_out, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}

int setmark_out_icmp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  nfct_set_attr_u32(mct, ATTR_MARK, nfmark_to_set_out_icmp);
  nfct_query(dummy_handle_setmark_out, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}

int setmark_in (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  nfmark_to_set_in += NFMARK_DELTA;
  nfct_set_attr_u32(mct, ATTR_MARK, nfmark_to_set_in);
  nfct_query(dummy_handle_setmark_in, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}

void  init_conntrack()
{
  u_int8_t family = AF_INET;
  //_nfct_new (ct_out_tcp);
  //_nfct_new (ct_out_udp);
  //_nfct_new (ct_out_icmp);
  //_nfct_new (ct_in);
  ct_out_tcp = nfct_new();
  if (ct_out_tcp == NULL){
    printf("nfct_new: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  ct_out_udp = nfct_new();
  if (ct_out_udp == NULL){
    printf("nfct_new: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  ct_out_icmp = nfct_new();
  if (ct_out_icmp == NULL){
    printf("nfct_new: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  ct_in = nfct_new();
  if (ct_in == NULL){
    printf("nfct_new: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  //_nfct_open (dummy_handle_delete, NFNL_SUBSYS_CTNETLINK, 0);
  dummy_handle_delete = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
  if (dummy_handle_delete == NULL){
    printf("nfct_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  //_nfct_query (dummy_handle_delete, NFCT_Q_FLUSH, &family);
  int retval = nfct_query(dummy_handle_delete, NFCT_Q_FLUSH, &family);
  if (retval == -1){
    printf("nfct_query: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  //_nfct_open (dummy_handle_setmark_out, NFNL_SUBSYS_CTNETLINK, 0);
  //_nfct_open (dummy_handle_setmark_in, NFNL_SUBSYS_CTNETLINK, 0);
  //_nfct_open (setmark_handle_out_tcp, NFNL_SUBSYS_CTNETLINK, 0);
  //_nfct_open (setmark_handle_out_udp, NFNL_SUBSYS_CTNETLINK, 0);
  //_nfct_open (setmark_handle_out_icmp, NFNL_SUBSYS_CTNETLINK, 0);
  //_nfct_open (setmark_handle_in, NFNL_SUBSYS_CTNETLINK, 0);
  dummy_handle_setmark_out = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
  if (dummy_handle_setmark_out == NULL){
    printf("nfct_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  dummy_handle_setmark_in = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
  if (dummy_handle_setmark_in == NULL){
    printf("nfct_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  setmark_handle_out_tcp = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
  if (setmark_handle_out_tcp == NULL){
    printf("nfct_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  setmark_handle_out_udp = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
  if (setmark_handle_out_udp == NULL){
    printf("nfct_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  setmark_handle_out_icmp = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
  if (setmark_handle_out_icmp == NULL){
    printf("nfct_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  setmark_handle_in = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
  if (setmark_handle_in == NULL){
    printf("nfct_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  //_nfct_callback_register (setmark_handle_out_tcp, NFCT_T_ALL, setmark_out_tcp, NULL);
  //_nfct_callback_register (setmark_handle_out_udp, NFCT_T_ALL, setmark_out_udp, NULL);
  //_nfct_callback_register (setmark_handle_out_icmp, NFCT_T_ALL, setmark_out_icmp, NULL);
  //_nfct_callback_register (setmark_handle_in, NFCT_T_ALL, setmark_in, NULL);
  retval = nfct_callback_register(setmark_handle_out_tcp, NFCT_T_ALL, setmark_out_tcp, NULL);
  if (retval == -1){
    printf("nfct_callback_register: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  retval = nfct_callback_register(setmark_handle_out_udp, NFCT_T_ALL, setmark_out_udp, NULL);
  if (retval == -1){
    printf("nfct_callback_register: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  retval = nfct_callback_register(setmark_handle_out_icmp, NFCT_T_ALL, setmark_out_icmp, NULL);
  if (retval == -1){
    printf("nfct_callback_register: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}
  retval = nfct_callback_register(setmark_handle_in, NFCT_T_ALL, setmark_in, NULL);
  if (retval == -1){
    printf("nfct_callback_register: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );}

  _pthread_create ( &tcp_export_thr, (pthread_attr_t *)NULL, tcp_export_thread, (void *)NULL);

}

void* tcp_export_thread ( void *ptr ) {
  ptr = 0;
  srand (time(NULL)+1);
  int sockfd, newsockfd, portno;
  socklen_t clilen;
  struct sockaddr_in serv_addr, cli_addr;
  int n;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) perror("ERROR opening socket");
  bzero((char *) &serv_addr, sizeof(serv_addr));
  do { portno = rand() % 65535;}
  while (portno < 1025);
  ofstream myfile("/tmp/ctport");
  myfile << std::to_string(portno);
  myfile.close();
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portno);
  if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
    perror("ERROR on binding");}
  listen(sockfd,5);
  clilen = sizeof(cli_addr);
  newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
  if (newsockfd < 0) perror("ERROR on accept");
  if(fcntl(newsockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0) {
    printf ("Couldn't set socket to non-blocking"); }

  string dispatch;
  while (true) {
    if (ctmsgQueue.empty()) {
      sleep(1);
      continue;
    }
    try { //TODO a race condition is possible when ct_dump_thread clears the queue
      dispatch = ctmsgQueue.front();
    } catch (...) {continue;}
    ctmsgQueue.pop();
    n = send(newsockfd, dispatch.c_str(), dispatch.length(), MSG_NOSIGNAL);
    if (n < 0) continue;
  }
}


int ct_delete_mark_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  int mark = nfct_get_attr_u32(mct, ATTR_MARK);
  if ( mark == nfmark_to_delete_in || mark == nfmark_to_delete_out)
    {
      if (nfct_query(dummy_handle_delete, NFCT_Q_DESTROY, mct) == -1)
	{
	  M_PRINTF ( MLOG_DEBUG, "nfct_query DESTROY %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	  return NFCT_CB_CONTINUE;
	}
      M_PRINTF ( MLOG_DEBUG, "deleted entry %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
      return NFCT_CB_CONTINUE;
    }
  return NFCT_CB_CONTINUE;
}

int ct_dump_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  int mark;
  ulong in_bytes, out_bytes;
  if ((mark = nfct_get_attr_u32(mct, ATTR_MARK)) == 0)
    {
      return NFCT_CB_CONTINUE;
    }
  out_bytes = nfct_get_attr_u64(mct, ATTR_ORIG_COUNTER_BYTES);
  in_bytes = nfct_get_attr_u64(mct, ATTR_REPL_COUNTER_BYTES);

  pthread_mutex_lock ( &ct_entries_mutex);
  int i;
  for (i = 0; ct_array[i][0] != 0; ++i)
    {
      if (ct_array[i][0] != mark) continue;
      ct_array[i][1] += in_bytes;
      ct_array[i][2] += out_bytes;
      pthread_mutex_unlock ( &ct_entries_mutex);
      return NFCT_CB_CONTINUE;
    }
  //the entry is not yet in array, adding now
  ct_array[i][0] = mark;
  ct_array[i][1] = in_bytes;
  ct_array[i][2] = out_bytes;
  pthread_mutex_unlock ( &ct_entries_mutex);
  return NFCT_CB_CONTINUE;
}

//When conntrack deletes an entry, we get called. Bump up the in/out bytes statistics
int ct_destroy_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  int mark;
  ulong in_bytes, out_bytes;
  if ((mark = nfct_get_attr_u32(mct, ATTR_MARK)) == 0)
    {
      //printf ("destroy nfmark 0 detected \n");
      return NFCT_CB_CONTINUE;
    }
  out_bytes = nfct_get_attr_u64(mct, ATTR_ORIG_COUNTER_BYTES);
  in_bytes = nfct_get_attr_u64(mct, ATTR_REPL_COUNTER_BYTES);

  int i;
  for (i = 0; ct_array[i][0] != 0; ++i)
    {
      if (ct_array[i][0] != mark) continue;
      ct_array[i][3] += in_bytes;
      ct_array[i][4] += out_bytes;
      return NFCT_CB_CONTINUE;
    }
  printf ("Error: there was a request to destroy nfmark which is not in the list \n");
  return NFCT_CB_CONTINUE;
}

void * thread_ct_dump( void *ptr)
{
  u_int8_t family = AF_INET;
  struct nfct_handle *ct_dump_handle;
  if ((ct_dump_handle = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if ((nfct_callback_register(ct_dump_handle, NFCT_T_ALL, ct_dump_cb, NULL) == -1))
    {
      perror("cb_reg");
    }


  while(1){
    //zero out from previous iteration
    int i;
    for (i=0; i<CT_ENTRIES_EXPORT_MAX; ++i){
      ct_array[i][1] = ct_array[i][2] = ct_array_export[i][0] = ct_array_export[i][1] =
		  ct_array_export[i][2] = ct_array_export[i][3] = ct_array_export[i][4] = 0;
    }
    _pthread_mutex_lock(&ct_dump_mutex);
    if (nfct_query(ct_dump_handle, NFCT_Q_DUMP, &family) == -1) perror("query-DELETE");
    _pthread_mutex_unlock(&ct_dump_mutex);
//we get here only when dumping operation finishes and traffic_callback has created a new array of
//conntrack entries
    _pthread_mutex_lock(&ct_entries_mutex);
    for (i = 0; ct_array[i][0] != 0; ++i){
      ct_array[i][5] = ct_array[i][1]+ct_array[i][3];
      ct_array[i][6] = ct_array[i][2]+ct_array[i][4];
    }
    //rearrange array for export
    int j;
    for (i=0; ct_array[i][0] != 0; ++i){
      for (j=0; ct_array_export[j][0] !=0; ++j) {
        //if this is an IN nfmark
        if (ct_array[i][0] >= NFMARKIN_BASE) {
          //find its OUT nfmark
          int delta = ct_array[i][0] - NFMARK_DELTA;
          if (delta == ct_array_export[j][0]){
            //bytes in for IN nfmark are bytes out for OUT nfmark
            ct_array_export[j][1] += ct_array[i][6];
            ct_array_export[j][2] += ct_array[i][5];
            ct_array_export[j][3] += ct_array[i][8];
            ct_array_export[j][4] += ct_array[i][7];
            goto next;
          }
        }
        //else if this is a OUT nfmark
        if (ct_array[i][0] == ct_array_export[j][0]){
          ct_array_export[j][1] += ct_array[i][5];
          ct_array_export[j][2] += ct_array[i][6];
          ct_array_export[j][3] += ct_array[i][7];
          ct_array_export[j][4] += ct_array[i][8];
          goto next;
        }
      }
      //Doesn't exist in export list, create an entry
      if (ct_array[i][0] >= NFMARKIN_BASE){
        ct_array_export[j][0] = ct_array[i][0] - NFMARK_DELTA;
        ct_array_export[j][1] = ct_array[i][6];
        ct_array_export[j][2] = ct_array[i][5];
        ct_array_export[j][3] = ct_array[i][8];
        ct_array_export[j][4] = ct_array[i][7];
      }
      else{
        ct_array_export[j][0] = ct_array[i][0];
        ct_array_export[j][1] = ct_array[i][5];
        ct_array_export[j][2] = ct_array[i][6];
        ct_array_export[j][3] = ct_array[i][7];
        ct_array_export[j][4] = ct_array[i][8];
      }
  next:
  ;
    }
  _pthread_mutex_unlock(&ct_entries_mutex);
  string export_string = "";
  for (j=0; ct_array_export[j][0] !=0; ++j) {
    export_string +=  std::to_string(ct_array_export[j][0]) + " " +
        std::to_string(ct_array_export[j][1]) + " " +
        std::to_string(ct_array_export[j][2]) + " " +
        std::to_string(ct_array_export[j][3]) + " " +
        std::to_string(ct_array_export[j][4]) + string(" CRLF ");
  }
  export_string += "EOL ";
  ctmsgQueue = queue<string>(); //clear the queue
  ctmsgQueue.push(export_string);
  sleep(1);
   }
}

void denied_traffic_add (const int direction, const int mark, const int bytes)
{
  int i;
    _pthread_mutex_lock ( &ct_entries_mutex);
    for (i = 0; ct_array[i][0] != 0; ++i)
      {
	if (ct_array[i][0] != mark) continue;
	if (direction == DIRECTION_OUT)
	{
	    ct_array[i][8] += bytes;
	}
	else if (direction == DIRECTION_IN)
	{
	    ct_array[i][7] += bytes;
	}
	_pthread_mutex_unlock ( &ct_entries_mutex);
	return;
      }
    //the entry is not yet in array, adding now
    ct_array[i][0] = mark;
    if (direction == DIRECTION_OUT)
    {
	ct_array[i][8] += bytes;
    }
    else if (direction == DIRECTION_IN)
    {
	ct_array[i][7] += bytes;
    }
    _pthread_mutex_unlock ( &ct_entries_mutex);
    return ;
}
