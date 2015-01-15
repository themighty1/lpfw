#include <errno.h>
#include <fstream>
#include <iomanip>
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
#include <sstream>
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
pthread_t ct_dump_thr, ct_destroy_hook_thr, ct_delete_ctmark_thr;

int ctmark_to_delete_in, ctmark_to_delete_out;
struct nfct_handle *setmark_handle;
extern bool conntrack_send_anyway;
extern void log(string);

//this array is used internally by lpfw to prepare for export
ulong ct_array[CT_ENTRIES_EXPORT_MAX][9] = {};
//this array is built for export to frontend based on ct_array
ulong ct_array_export[CT_ENTRIES_EXPORT_MAX][5] = {};
/*
  [0] ctmark (export[0])
  [1] bytes in allowed
  [2] bytes out allowed
  [3] bytes in from all previously destroyed conntracks which had this ctmark
  [4] bytes out from all previously destroyed conntracks which had this ctmark
  [5] [1] + [3] (export[1])
  [6] [2] + [4] (export[2])
  [7] total bytes in denied so far  (export[3])
  [8] total bytes out denied so far (export[4])
*/


//Register a callback ct_destroy_cb that gets triggered whenever conntrack tries to destroy a connection
//TODO: this is a weirdly-written old function. there is no need to block here.
void * thread_ct_destroy( void *ptr)
{
  struct nfct_handle *traffic_handle = _nfct_open(NFNL_SUBSYS_CTNETLINK, NF_NETLINK_CONNTRACK_DESTROY);
  _nfct_callback_register(traffic_handle, NFCT_T_DESTROY, ct_destroy_cb, (void *)NULL);
  nfct_catch(traffic_handle); //the thread should block here
}


//lpfw triggers condvar condition when a rule is deleted.
//this thread will DUMP all conntracks onto ct_delete_mark_cb one by one
void* thread_ct_delete_mark ( void* ptr )
{
  u_int8_t family = AF_INET;
  struct nfct_handle *deletemark_handle = _nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
  _nfct_callback_register(deletemark_handle, NFCT_T_ALL, ct_delete_mark_cb, (void *)NULL);

  while(1){
    _pthread_mutex_lock(&condvar_mutex);
    while(predicate == FALSE){
      pthread_cond_wait(&condvar, &condvar_mutex);
    }
    predicate = FALSE;
    _pthread_mutex_unlock(&condvar_mutex);
    _pthread_mutex_lock(&ct_dump_mutex);
    _nfct_query(deletemark_handle, NFCT_Q_DUMP, &family);
    _pthread_mutex_unlock(&ct_dump_mutex);
  }
}


//Set netfilter mark on a connection
int setmark (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  static nfct_handle *handle = _nfct_open (NFNL_SUBSYS_CTNETLINK, 0);
  nfct_set_attr_u32(mct, ATTR_MARK, ctmark_to_set);
  nfct_query(handle, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}


void init_conntrack(){
  //enable byte accounting in conntrack
  ofstream file("/proc/sys/net/netfilter/nf_conntrack_acct");
  file << "1";
  file.close();
  //Flush all conntrack entries so that we're getting a fresh start
  u_int8_t family = AF_INET;
  nfct_handle *handle_flush = _nfct_open (NFNL_SUBSYS_CTNETLINK, 0);
  _nfct_query (handle_flush, NFCT_Q_FLUSH, &family);
  //register a callback which nfq_handler will call to set netfilter marks on connection
  setmark_handle = _nfct_open (NFNL_SUBSYS_CTNETLINK, 0);
   _nfct_callback_register (setmark_handle, NFCT_T_ALL, setmark, (void *)NULL);

  _pthread_create ( &tcp_export_thr, (pthread_attr_t *)NULL, tcp_export_thread, (void *)NULL);
  _pthread_create ( &ct_dump_thr, (pthread_attr_t *)NULL, thread_ct_dump, (void *)NULL );
  _pthread_create ( &ct_destroy_hook_thr, (pthread_attr_t *)NULL, thread_ct_destroy, (void *)NULL);
  _pthread_create ( &ct_delete_ctmark_thr, (pthread_attr_t *)NULL, thread_ct_delete_mark, (void *)NULL);
}


void* tcp_export_thread ( void *ptr ) {
  ptr = 0;
  int sockfd, newsockfd;
  socklen_t clilen;
  struct sockaddr_in serv_addr, cli_addr;
  int n;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) perror("ERROR opening socket");
  bzero((char *) &serv_addr, sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(0);
  if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
    perror("ERROR on binding");
  }
  int local_port;
  struct sockaddr_in sin;
  socklen_t addrlen = sizeof(sin);
  if(getsockname(sockfd, (struct sockaddr *)&sin, &addrlen) == 0 &&
    sin.sin_family == AF_INET && addrlen == sizeof(sin)) {
    local_port = ntohs(sin.sin_port);
  }
  log("Conntrack port:"+to_string(local_port));
  ofstream myfile("/tmp/lpfwctport");
  myfile << std::to_string(local_port);
  myfile.close();

  string dispatch;
  while (true) {
    listen(sockfd,1);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0) perror("ERROR on accept");
    if(fcntl(newsockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0) {
      printf ("Couldn't set socket to non-blocking"); }

    while(true){
      if (ctmsgQueue.empty()) {
        sleep(1);
        continue;
      }
      try { //TODO a race condition is possible when ct_dump_thread clears the queue
        dispatch = ctmsgQueue.front();
      } catch (...) {continue;}
      ctmsgQueue.pop();
      n = send(newsockfd, dispatch.c_str(), dispatch.length(), MSG_NOSIGNAL);
      if (n < 0) {break;};
    }
  }
}


//delete conntracks which have the mark
int ct_delete_mark_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  static nfct_handle *handle_delete = _nfct_open (NFNL_SUBSYS_CTNETLINK, 0);
  int mark = nfct_get_attr_u32(mct, ATTR_MARK);
  if ( mark == ctmark_to_delete_in || mark == ctmark_to_delete_out){
    if (nfct_query(handle_delete, NFCT_Q_DESTROY, mct) == -1){
      printf("Error: nfct_query DESTROY %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
      return NFCT_CB_CONTINUE;
    }
    log("deleted ct mark:"+to_string(mark));
    return NFCT_CB_CONTINUE;
  }
  return NFCT_CB_CONTINUE;
}


//Receive one-by-one all conntracks and add current byte count
//to the previous
int ct_dump_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  int i,mark;
  ulong in_bytes, out_bytes;
  if ((mark = nfct_get_attr_u32(mct, ATTR_MARK)) == 0){
    return NFCT_CB_CONTINUE;}
  out_bytes = nfct_get_attr_u64(mct, ATTR_ORIG_COUNTER_BYTES);
  in_bytes = nfct_get_attr_u64(mct, ATTR_REPL_COUNTER_BYTES);

  //No need to lock mutex here b/c it's being held by thread_ct_dump which called us
  for (i = 0; ct_array[i][0] != 0; ++i)
    {
      if (ct_array[i][0] != mark) continue;
      ct_array[i][1] += in_bytes;
      ct_array[i][2] += out_bytes;
      return NFCT_CB_CONTINUE;
    }
  //the entry is not yet in array, adding now
  ct_array[i][0] = mark;
  ct_array[i][1] = in_bytes;
  ct_array[i][2] = out_bytes;
  return NFCT_CB_CONTINUE;
}


//When conntrack deletes an entry, we get called so we could
//correctly work out the in/out bytes statistics
int ct_destroy_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  int i,mark;
  bool scanned_twice = false;
  ulong in_bytes, out_bytes;
  if ((mark = nfct_get_attr_u32(mct, ATTR_MARK)) == 0){
    u_int32_t src_addr = nfct_get_attr_u32(mct, ATTR_ORIG_IPV4_SRC);
    u_int32_t dst_addr = nfct_get_attr_u32(mct, ATTR_ORIG_IPV4_DST);
    if (src_addr == dst_addr){
      //This is assumed to be local traffic. This looks to be a safe assumption
      //Ideally, we should query what our local interfaces are
      return NFCT_CB_CONTINUE;
    }
    //addr is in BE byte order. If MSB == 127, we are dealing with loopback range
    if ((src_addr & 0xFF) == 127 && (dst_addr & 0xFF) == 127){
      return NFCT_CB_CONTINUE;
    }
    //TODO: find out if it is OK if some conntracks dont have a mark
    //TODO check the conntracks timestamp
    out_bytes = nfct_get_attr_u64(mct, ATTR_ORIG_COUNTER_BYTES);
    in_bytes = nfct_get_attr_u64(mct, ATTR_REPL_COUNTER_BYTES);
    if (in_bytes != 0 && out_bytes != 0){
      log("Error: conntrack with mark 0 detected with leaked bytes");
      log("src_addr:"+to_string(src_addr));
      log("dst_addr:"+to_string(dst_addr));
      //TODO figure out a long-term solution for this rare problem
      //abort();
    }
    //else
    return NFCT_CB_CONTINUE;
  }
  //orig/repl will be treated as in/out later depending on the direction
  out_bytes = nfct_get_attr_u64(mct, ATTR_ORIG_COUNTER_BYTES);
  in_bytes = nfct_get_attr_u64(mct, ATTR_REPL_COUNTER_BYTES);

scan_again:
  pthread_mutex_lock ( &ct_entries_mutex);
  for (i = 0; ct_array[i][0] != 0; ++i){
    if (ct_array[i][0] != mark) continue;
    ct_array[i][3] += in_bytes;
    ct_array[i][4] += out_bytes;
    pthread_mutex_unlock ( &ct_entries_mutex);
    return NFCT_CB_CONTINUE;
  }
  pthread_mutex_unlock ( &ct_entries_mutex);
  //We have a mark that is not yet in ct_array. Maybe the dump thread (which sleeps every second)
  //hasn't added it yet. Give it another chance
  if (!scanned_twice){
    scanned_twice = true;
    sleep(1);
    log("************Scanning again in ct_destroy_cb");
    goto scan_again;
  }
  log("Error: unknown conntrack mark in ct_destroy_cb even after scanning again:"+to_string(mark));
  return NFCT_CB_CONTINUE;
  //TODO this error should be logged with a dump and analyzed
}


//Periodically dump all conntrack stats so we could tell the frontend
//per-process how many bytes went in/out and were allowed/denied
void * thread_ct_dump( void *ptr)
{
  u_int8_t family = AF_INET;
  struct nfct_handle *ct_dump_handle = _nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
  _nfct_callback_register(ct_dump_handle, NFCT_T_ALL, ct_dump_cb, (void *)NULL);

  int i,j;
  string export_string;
  string prev_export_string;
  while(1){
    _pthread_mutex_lock(&ct_entries_mutex);
    for (i=0; i<CT_ENTRIES_EXPORT_MAX; ++i){
      //zero out from previous iterations
      ct_array[i][1] = ct_array[i][2] = ct_array_export[i][0] = ct_array_export[i][1] =
		  ct_array_export[i][2] = ct_array_export[i][3] = ct_array_export[i][4] = 0;
    }
    _pthread_mutex_lock(&ct_dump_mutex);
    _nfct_query(ct_dump_handle, NFCT_Q_DUMP, &family);
    //nfct_query blocks until dumping completes and ct_dump_cb returns
    _pthread_mutex_unlock(&ct_dump_mutex);
    for (i = 0; ct_array[i][0] != 0; ++i){
      ct_array[i][5] = ct_array[i][1]+ct_array[i][3];
      ct_array[i][6] = ct_array[i][2]+ct_array[i][4];
    }
    //rearrange array for export
    for (i=0; ct_array[i][0] != 0; ++i){
      for (j=0; ct_array_export[j][0] !=0; ++j) {
        //if this is an IN ctmark
        if (ct_array[i][0] >= CTMARKIN_BASE) {
          //find its OUT ctmark
          int delta = ct_array[i][0] - CTMARK_DELTA;
          if (delta == ct_array_export[j][0]){
            //bytes in for IN ctmark are bytes out for OUT ctmark
            ct_array_export[j][1] += ct_array[i][6];
            ct_array_export[j][2] += ct_array[i][5];
            ct_array_export[j][3] += ct_array[i][8];
            ct_array_export[j][4] += ct_array[i][7];
            goto next;
          }
        }
        //else if this is a OUT ctmark
        if (ct_array[i][0] == ct_array_export[j][0]){
          ct_array_export[j][1] += ct_array[i][5];
          ct_array_export[j][2] += ct_array[i][6];
          ct_array_export[j][3] += ct_array[i][7];
          ct_array_export[j][4] += ct_array[i][8];
          goto next;
        }
      }
      //Doesn't exist in export list, create an entry
      if (ct_array[i][0] >= CTMARKIN_BASE){
        ct_array_export[j][0] = ct_array[i][0] - CTMARK_DELTA;
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
    export_string.clear();
    for (j=0; ct_array_export[j][0] !=0; ++j) {
      export_string +=  std::to_string(ct_array_export[j][0]) + " " +
          std::to_string(ct_array_export[j][1]) + " " +
          std::to_string(ct_array_export[j][2]) + " " +
          std::to_string(ct_array_export[j][3]) + " " +
          std::to_string(ct_array_export[j][4]) + string(" CRLF ");
    }
    export_string += "EOL ";
    //Only send updates to frontend when stats changed
    if ((export_string != prev_export_string) || (conntrack_send_anyway)){
      ctmsgQueue = queue<string>(); //clear the queue
      ctmsgQueue.push(export_string);
      prev_export_string = export_string;
      if (conntrack_send_anyway) {
        log("toggling conntrack_send_anyway to false");
        conntrack_send_anyway = false;}
    }
  sleep(1);
  }
}


void denied_traffic_add (const int direction, const int mark, const int bytes)
{
  int i;
  _pthread_mutex_lock ( &ct_entries_mutex);
  for (i = 0; ct_array[i][0] != 0; ++i){
    if (ct_array[i][0] != mark) continue;
    if (direction == DIRECTION_OUT){
	    ct_array[i][8] += bytes;
    }
    else if (direction == DIRECTION_IN){
	    ct_array[i][7] += bytes;
    }
    _pthread_mutex_unlock ( &ct_entries_mutex);
    return;
  }
  //the entry is not yet in array, adding now
  ct_array[i][0] = mark;
  if (direction == DIRECTION_OUT){
    ct_array[i][8] += bytes;
  }
  else if (direction == DIRECTION_IN){
    ct_array[i][7] += bytes;
  }
  _pthread_mutex_unlock ( &ct_entries_mutex);
  return ;
}
