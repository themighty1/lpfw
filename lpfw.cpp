#include <arpa/inet.h> //for ntohl()
#include <assert.h>
#include <ctype.h> // for toupper
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <grp.h>
#include <dirent.h>
#include <iostream>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter.h> //for NF_ACCEPT, NF_DROP etc
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <queue>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h> //for malloc
#include <string>
#include <string.h>
#include <sys/capability.h>
#include <sys/ipc.h>
#include <sys/mman.h> //for mmap
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h> //required for netfilter.h
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h> //for print_trace
#include <syslog.h>
#include <time.h>       /* time */
#include <unistd.h>
#include <vector>

#include "argtable/argtable2.h"
#include "common/defines.h"
#include "common/includes.h"
#include "lpfw.h"
#include "common/syscall_wrappers.h"
#include "conntrack.h"
#include "version.h" //for version string during packaging
#include "sha256/sha256.h"

using namespace std;

queue<string> rulesListQueue;
queue<string> requestQueue;

//should be available globally to call nfq_close from sigterm handler
struct nfq_handle *globalh_out_tcp, *globalh_out_udp, *globalh_out_rest, *globalh_in, *globalh_gid;

//command line arguments available globally
struct arg_str *logging_facility;
struct arg_file *rules_file, *pid_file, *log_file, *allow_rule;
struct arg_int *log_info, *log_traffic, *log_debug;
struct arg_lit *test;
//Paths of various frontends kept track of in order to chown&chmod them
struct arg_file *cli_path, *gui_path, *pygui_path;

FILE *fileloginfo_stream, *filelogtraffic_stream, *filelogdebug_stream;

//first element of dlist is an empty one,serves as reference to determine the start of dlist
vector<rule> rules; //each rules contains path,permission,hash

global_rule_t *first_global_rule = NULL;
int fe_pid;
//pointer to the actual logging function
int ( *m_printf ) ( const int loglevel, const char *logstring );

//mutex to protect ruleslist AND nfmark_count
pthread_mutex_t dlist_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_t refresh_thr, nfq_in_thr, cache_build_thr, nfq_out_udp_thr, nfq_out_rest_thr, ct_dump_thr,
ct_destroy_hook_thr, read_stats_thread, ct_delete_nfmark_thr, frontend_poll_thr, nfq_gid_thr,
unittest_thr, rules_dump_thr, tcp_server_thr, test_thr;

//flag which shows whether frontend is running
bool fe_active_flag = true;
pthread_mutex_t fe_active_flag_mutex = PTHREAD_MUTEX_INITIALIZER;
//fe_was_busy_* is a flag to know whether frontend was processing another "add" request from lpfw
//Normally, if path is not found in ruleslist, we send a request to frontend
//But in case it was busy when we started packet_handle_*, we assume FRONTEND_BUSY
//This prevents possible duplicate entries in ruleslist
bool fe_was_busy_in, fe_was_busy_out;

//mutexed string which threads use for logging
pthread_mutex_t logstring_mutex = PTHREAD_MUTEX_INITIALIZER;
char logstring[PATHSIZE];

FILE *tcpinfo, *tcp6info, *udpinfo, *udp6info;
int tcpinfo_fd, tcp6info_fd, udpinfo_fd, udp6info_fd, procnetrawfd;

int nfqfd_input, nfqfd_tcp, nfqfd_udp, nfqfd_rest, nfqfd_gid;

//track time when last packet was seen to put to sleep some threads when there is no traffic
struct timeval lastpacket = {0};
pthread_mutex_t lastpacket_mutex = PTHREAD_MUTEX_INITIALIZER;

//netfilter mark number for the packet (to be summed with NF_MARK_BASE)
int nfmark_count = 0;
//for debug purposed - how many times read() was called
int tcp_stats, udp_stats;
//cache that holds correlation of ports<-->sockets from various /proc/net/* files
int tcp_port_and_socket_cache[MEMBUF_SIZE], udp_port_and_socket_cache[MEMBUF_SIZE],
tcp6_port_and_socket_cache[MEMBUF_SIZE], udp6_port_and_socket_cache[MEMBUF_SIZE];
bool awaiting_reply_from_fe = false;


void print_trace() {
    char pid_buf[30];
    sprintf(pid_buf, "%d", getpid());
    char name_buf[512];
    name_buf[readlink("/proc/self/exe", name_buf, 511)]=0;
    int child_pid = fork();
    if (!child_pid) {
        dup2(2,1); // redirect output to stderr
        fprintf(stdout,"stack trace for %s pid=%s\n",name_buf,pid_buf);
        execlp("gdb", "gdb", "--batch", "-n", "-ex", "thread", "-ex", "bt", name_buf, pid_buf, NULL);
        abort(); /* If gdb failed to start */
    } else {
        waitpid(child_pid,NULL,0);
    }
}


void die(string message = ""){
  if (message != "") cout << message << "\n";
  print_trace();
}


void fe_active_flag_set ( const unsigned char boolean )
{
  _pthread_mutex_lock ( &fe_active_flag_mutex );
  fe_active_flag = boolean;
  _pthread_mutex_unlock ( &fe_active_flag_mutex );
}

void capabilities_modify(const int capability, const int set, const int action)
{
    cap_t cap_current;
    const cap_value_t caps_list[] = {capability};

    cap_current = _cap_get_proc();
    _cap_set_flag(cap_current, (cap_flag_t)set, 1, caps_list, (cap_flag_value_t)action);
    _cap_set_proc(cap_current);
}


int build_port_and_socket_cache(unsigned long &socket_out, const int port_in, int mode) {
    char smallbuf[4096];
    char newline[2] = {'\n','\0'};
    int bytesread, port, i, procnet_fd, *cache;
    bool bSocketFound = false;
    long socket;
    char *token, *lasts;
    FILE *procnet_file;
    if (mode == CACHE_TCP) {
      procnet_file = tcpinfo;
      procnet_fd = tcpinfo_fd;
      cache = tcp_port_and_socket_cache;
    }
    else if (mode == CACHE_TCP6) {
      procnet_file = tcp6info;
      procnet_fd = tcp6info_fd;
      cache = tcp6_port_and_socket_cache;
    }
    else if (mode == CACHE_UDP) {
      procnet_file = udpinfo;
      procnet_fd = udpinfo_fd;
      cache = udp_port_and_socket_cache;
    }
    else if (mode == CACHE_UDP6) {
      procnet_file = udp6info;
      procnet_fd = udp6info_fd;
      cache = udp6_port_and_socket_cache;
    }
    i = 0;
    memset(smallbuf,0,4096);
    _fseek(procnet_file,0,SEEK_SET);
    while ((bytesread = read(procnet_fd, smallbuf, 4060)) > 0) {
      if (bytesread == -1) { die(strerror(errno)); }
      token = strtok_r(smallbuf, newline, &lasts); //skip the first line (column headers)
      while ((token = strtok_r(NULL, newline, &lasts)) != NULL) {
        //take a line until EOF
        sscanf(token, "%*s %*[0123456789ABCDEF]:%4X %*s %*s %*s %*s %*s %*s %*s %ld \n", &port, &socket);
        cache[i*2] = (unsigned long)port;
        cache[i*2+1] = socket;
        if (port_in == port) {
          socket_out = socket;
          bSocketFound = true;
        }
        i++;
      }
    }
    cache[i*2] = (unsigned long)MAGIC_NO;
    if (!bSocketFound) { return 0; }
    else { return 1; }
}


//For debug purposes only - measure read()s per second on /proc/net* files
void * readstatsthread( void *ptr)
{
  static int old_tcp_stats;
  static int old_udp_stats;

  old_tcp_stats = 0;
  old_udp_stats = 0;
  int new_tcp_stats, new_udp_stats;

  while(1)
    {
      sleep(1);
      new_tcp_stats = tcp_stats - old_tcp_stats;
      new_udp_stats = udp_stats - old_udp_stats;
      printf (" %d %d \n", new_tcp_stats, new_udp_stats);
      old_tcp_stats = tcp_stats;
      old_udp_stats = udp_stats;
    }
}


int fe_active_flag_get()
{
  _pthread_mutex_lock ( &fe_active_flag_mutex );
  bool temp = fe_active_flag;
  _pthread_mutex_unlock ( &fe_active_flag_mutex );
  return temp;
}


int m_printf_stdout ( const int loglevel, const char * logstring )
{
  switch ( loglevel )
    {
    case MLOG_INFO:
      // check if INFO logging enabled
      if ( !* ( log_info->ival ) ) return 0;
      printf ( "%s", logstring );
      return 0;
    case MLOG_TRAFFIC:
      if ( !* ( log_traffic->ival ) ) return 0;
      printf ( "%s", logstring );
      return 0;
    case MLOG_DEBUG:
      if ( !* ( log_debug->ival ) ) return 0;
      printf ( "%s", logstring );
      return 0;
    case MLOG_DEBUG2:
#ifdef DEBUG2
      if ( !* ( log_debug->ival ) ) return 0;
      printf ( "%s", logstring );
#endif
      return 0;
    case MLOG_DEBUG3:
#ifdef DEBUG3
      if ( !* ( log_debug->ival ) ) return 0;
      printf ( "%s", logstring );
#endif
      return 0;
    case MLOG_ALERT: //Alerts get logged unconditionally to all log channels
      printf ( "ALERT: " );
      printf ( "%s", logstring );
      return 0;
    }
}


//technically vfprintf followed by fsync should be enough, but for some reason on my system it can take more than 1 minute before data gets actually written to disk. So until the mystery of such a huge delay is solved, we use write() so data gets written to dist immediately
int m_printf_file ( const int loglevel, const char * logstring )
{
  switch ( loglevel )
    {
    case MLOG_INFO:
      // check if INFO logging enabled
      if ( !* ( log_info->ival ) ) return 0;
      write ( fileno ( fileloginfo_stream ), logstring, strlen ( logstring ) );
      return 0;
    case MLOG_TRAFFIC:
      if ( !* ( log_traffic->ival ) ) return 0;
      write ( fileno ( filelogtraffic_stream ), logstring, strlen ( logstring ) );
      return 0;
    case MLOG_DEBUG:
      if ( !* ( log_debug->ival ) ) return 0;
      write ( fileno ( filelogdebug_stream ), logstring, strlen ( logstring ) );
      return 0;
    case MLOG_ALERT: //Alerts get logged unconditionally to all log channels
      write ( fileno ( filelogdebug_stream ), "ALERT: ", strlen ( logstring ) );
      return 0;
    }
}


#ifndef WITHOUT_SYSLOG
int m_printf_syslog (const int loglevel, const char * logstring)
{
  switch ( loglevel )
    {
    case MLOG_INFO:
      // check if INFO logging enabled
      if ( !* ( log_info->ival ) ) return 0;
      syslog ( LOG_INFO, "%s", logstring );
      return 0;
    case MLOG_TRAFFIC:
      if ( !* ( log_traffic->ival ) ) return 0;
      syslog ( LOG_INFO, "%s", logstring );
      return 0;
    case MLOG_DEBUG:
      if ( !* ( log_debug->ival ) ) return 0;
      syslog ( LOG_INFO, "%s", logstring );
      return 0;
    case MLOG_ALERT: //Alerts get logget unconditionally to all log channels
      syslog ( LOG_INFO, "ALERT: " );
      syslog ( LOG_INFO, "%s", logstring );
      return 0;
    }
}
#endif


unsigned long long starttimeGet ( const int mypid ) {
  unsigned long long starttime;
  FILE *stream;
  string path = string("/proc/") + to_string(mypid) + string("/stat");
  stream = _fopen (path.c_str(), "r" );
  fscanf ( stream, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s"
           "%*s %*s %*s %*s %*s %*s %*s %llu", &starttime );
  _fclose ( stream );
  return starttime;
}


int ruleslist_add( const string path, const string pid, const string perms,
                   const bool active, const string sha, const unsigned long long stime,
                   const int nfmark, const bool first_instance){
  int retnfmark;
  int i;
  _pthread_mutex_lock ( &dlist_mutex );
  if (path == KERNEL_PROCESS) {
    //make sure it is not a duplicate KERNEL_PROCESS
    for(i=0; i < rules.size(); i++){
      if (rules[i].path != KERNEL_PROCESS) continue;
      if (rules[i].pid == pid) { //same IP, quit
         die();
        _pthread_mutex_unlock ( &dlist_mutex );
        return 0;
      }
    }
  }
  else {
    //make sure it's not a duplicate of a regular (i.e. non-kernel) rule
    for(i=0; i < rules.size(); i++){
      if (rules[i].path == path && rules[i].pid == pid){
        die();
        _pthread_mutex_unlock ( &dlist_mutex );
        return 0;
      }
    }
  }
  rule newrule;
  newrule.path = path;
  newrule.pid = pid;
  newrule.perms = perms;
  newrule.is_active = active;
  newrule.stime = stime;
  newrule.sha = sha;
  if (nfmark == 0) {
    newrule.nfmark_in = NFMARKIN_BASE + nfmark_count;
    retnfmark = newrule.nfmark_out = NFMARKOUT_BASE +  nfmark_count;
    nfmark_count++;
  }
  else { // nfmark > 0 => assign parent's nfmark
    //either nfmark is for in or out traffic
    if (nfmark >= NFMARKIN_BASE){
      newrule.nfmark_in = nfmark;
      retnfmark = newrule.nfmark_out = nfmark - NFMARK_DELTA;
    }
    else {
      retnfmark = newrule.nfmark_out = nfmark;
      newrule.nfmark_in = nfmark + NFMARK_DELTA;
    }
    nfmark_count++;
  }
  newrule.first_instance = first_instance;
  if (newrule.is_active && newrule.path != KERNEL_PROCESS){
    newrule.pidfdpath = "/proc/" + newrule.pid + "/fd/";
    newrule.dirstream = _opendir (newrule.pidfdpath.c_str());
//    try {
//      newrule.dirstream = _opendir (newrule.pidfdpath.c_str());
//    } catch(...) {
//      //TODO investigate this scenario:
//      //An app forks to send a packet. When we add the rule, the forked pid already
//      //terminated
//      printf("CAUGHT EXCEEEEEEEEEEEEEEEEPTION");
//      newrule.dirstream = NULL;
//    }
  }
  if ((newrule.sockets_cache = (long*)malloc(sizeof(long)*MAX_CACHE)) == NULL) perror("malloc");
  *newrule.sockets_cache = MAGIC_NO;
  rules.push_back(newrule);
  _pthread_mutex_unlock ( &dlist_mutex );
  if (perms == ALLOW_ALWAYS || perms == DENY_ALWAYS) {
    rulesfileWrite();
  }
  return retnfmark;
}


void ruleslist_delete_all ( const string path) {
  bool bRulesChanged = false;
  bool bNeedToWriteRulesfile = false;
  _pthread_mutex_lock ( &dlist_mutex );
  for(int i=0; i < rules.size(); i++){
    if (rules[i].path != path) continue;
    if (rules[i].is_active) {
      free(rules[i].sockets_cache);
      _closedir (rules[i].dirstream);
      nfmark_to_delete_in = rules[i].nfmark_in;
      nfmark_to_delete_out = rules[i].nfmark_out;
    }
    bool was_active = rules[i].is_active;
    if (rules[i].perms == ALLOW_ALWAYS || rules[i].perms == DENY_ALWAYS){
      bNeedToWriteRulesfile = true;
    }
    rules.erase(rules.begin()+i);
    --i; //revisit the same index again
    bRulesChanged = true;
    //remove tracking for this app's active connection only if this app was active
    if (was_active) {
      _pthread_mutex_lock(&condvar_mutex);
      predicate = TRUE;
      _pthread_mutex_unlock(&condvar_mutex);
      _pthread_cond_signal(&condvar);
    }
  }
  _pthread_mutex_unlock ( &dlist_mutex );
  if (! bRulesChanged) die(); //couldnt find the rule
  if (bNeedToWriteRulesfile) rulesfileWrite();
    if (fe_active_flag_get()) {
      string message = "RULES_LIST ";
      for(int k=0; k < rules.size(); k++){
        string is_active = rules[k].is_active ? "TRUE": "FALSE";
        message += rules[k].path + " " + rules[k].pid + " " + rules[k].perms + " "
            + is_active + " " + to_string(rules[k].nfmark_out) + " CRLF ";
      }
      message += " EOL ";
      rulesListQueue.push(message);
  }
}


//the calling thread holds the dlist mutex
void ruleslist_delete_one ( const string path, const string pid ) {
  for(int i=0; i < rules.size(); i++){
    if (rules[i].path != path || rules[i].pid != pid) continue;
    free(rules[i].sockets_cache);
    _closedir (rules[i].dirstream);
    nfmark_to_delete_in = rules[i].nfmark_in;
    nfmark_to_delete_out = rules[i].nfmark_out;
    bool was_active = rules[i].is_active;
    rules.erase(rules.begin()+i);
    //remove tracking for this app's active connection only if this app was active
    if (was_active) {
      _pthread_mutex_lock(&condvar_mutex);
      predicate = TRUE;
      _pthread_mutex_unlock(&condvar_mutex);
      _pthread_cond_signal(&condvar);
    }
    if (fe_active_flag_get()) {

      string message = "RULES_LIST ";
      for(int k=0; k < rules.size(); k++){
        string is_active = rules[k].is_active ? "TRUE": "FALSE";
        message += rules[k].path + " " + rules[k].pid + " " + rules[k].perms + " "
            + is_active + " " + to_string(rules[k].nfmark_out) + " CRLF ";
      }
      message += " EOL ";
      rulesListQueue.push(message);

    }
    return; // and return
  }
  die(); //couldnt find the rule to delete
}


int search_pid_and_socket_cache_in(const long socket_in, string &path_out,
                                   string &pid_out, int &nfmark_out){
  _pthread_mutex_lock ( &dlist_mutex );
  vector<rule> rulescopy = rules;
  //TODO is this how we copy the vector?
  _pthread_mutex_unlock ( &dlist_mutex );
  for(int i = 0; i < rulescopy.size(); i++){
    if (! rulescopy[i].is_active) continue;
    int j = 0;
    while (rulescopy[i].sockets_cache[j] != (long)MAGIC_NO) {
      if (j >= MAX_CACHE-1) break;
      if (rulescopy[i].sockets_cache[j] != socket_in) {
        j++;
        continue;
      }
      int retval;
      if (rulescopy[i].perms == ALLOW_ONCE || rulescopy[i].perms == ALLOW_ALWAYS) retval = CACHE_TRIGGERED_ALLOW;
      else retval = CACHE_TRIGGERED_DENY;
      path_out = rulescopy[i].path;
      pid_out = rulescopy[i].pid;
      if (rulescopy[i].stime != starttimeGet(atoi (rulescopy[i].pid.c_str()))) {return SPOOFED_PID;}
      nfmark_out = rulescopy[i].nfmark_out;
      return retval;
    }
  }
  return SOCKETS_CACHE_NOT_FOUND;
}


int search_pid_and_socket_cache_out(const long socket_in, string &path_out,
                                    string &pid_out, int &nfmark_out){
  _pthread_mutex_lock ( &dlist_mutex );
  vector<rule> rulescopy = rules;
  //TODO is this how we copy the vector?
  _pthread_mutex_unlock ( &dlist_mutex );
  for(int i = 0; i < rulescopy.size(); i++){
    if (! rulescopy[i].is_active) continue;
    int j = 0;
    while (rulescopy[i].sockets_cache[j] != (long)MAGIC_NO) {
      if (j >= MAX_CACHE-1) break;
      if (rulescopy[i].sockets_cache[j] != socket_in) {
        j++;
        continue;
      }
      int retval;
      if (rulescopy[i].perms == ALLOW_ONCE || rulescopy[i].perms == ALLOW_ALWAYS) retval = CACHE_TRIGGERED_ALLOW;
      else retval = CACHE_TRIGGERED_DENY;
      path_out = rulescopy[i].path;
      pid_out = rulescopy[i].pid;
      int stime;
      try { stime = starttimeGet(atoi (rulescopy[i].pid.c_str()));
      } catch (...) { return SOCKETS_CACHE_NOT_FOUND; }
      if (rulescopy[i].stime != stime) {
        return SPOOFED_PID;}
      nfmark_out = rulescopy[i].nfmark_out;
      return retval;
    }
  }
  return SOCKETS_CACHE_NOT_FOUND;
}


void* thread_build_pid_and_socket_cache ( void *ptr ){
  char proc_pid_exe[32];
  string proc_pid_fd_path;
  struct timespec refresh_timer,dummy;
  refresh_timer.tv_sec=0;
  refresh_timer.tv_nsec=1000000000/4;
  struct dirent *m_dirent;
  struct timeval time;
  int delta;

  while (true) {
    nanosleep(&refresh_timer, &dummy);
    gettimeofday(&time, NULL);
    _pthread_mutex_lock(&lastpacket_mutex);
    delta = time.tv_sec - lastpacket.tv_sec;
    _pthread_mutex_unlock(&lastpacket_mutex);
    if (delta > 1) continue;

    _pthread_mutex_lock ( &dlist_mutex );
    for(int i = 0; i < rules.size(); i++){
      if (! rules[i].is_active || rules[i].path == KERNEL_PROCESS) continue;
      rewinddir(rules[i].dirstream);
      errno=0;
      int j = 0;
      while (m_dirent = readdir ( rules[i].dirstream )){
        proc_pid_fd_path = rules[i].pidfdpath + m_dirent->d_name;
        memset (proc_pid_exe, 0 , sizeof(proc_pid_exe));
        if (readlink ( proc_pid_fd_path.c_str(), proc_pid_exe, SOCKETBUFSIZE ) == -1) {  //not a symlink but . or ..
          errno=0;
          continue;
        }
        if (proc_pid_exe[7] != '[') continue; //not a socket
        char *end;
        end = strrchr(&proc_pid_exe[8],']'); //put 0 instead of ]
        *end = 0;
        rules[i].sockets_cache[j] = atol(&proc_pid_exe[8]);
        j++;
      } //while (m_dirent = readdir ( rule->dirstream ))
      rules[i].sockets_cache[j] = MAGIC_NO;
      if (errno==0) continue; //readdir reached EOF, thus errno hasn't changed from 0
      else die();
    }
    _pthread_mutex_unlock ( &dlist_mutex );
  } // while(true)
}


void* thread_nfq_out_udp ( void *ptr )
{
  ptr = 0;
  //endless loop of receiving packets and calling a handler on each packet
  int rv;
  char buf[4096] __attribute__ ( ( aligned ) );
  while ( ( rv = recv ( nfqfd_udp, buf, sizeof ( buf ), 0 ) ) && rv >= 0 ){
    nfq_handle_packet ( globalh_out_udp, buf, rv );
  }
}


void* thread_nfq_out_rest ( void *ptr )
{
  ptr = 0;
  //endless loop of receiving packets and calling a handler on each packet
  int rv;
  char buf[4096] __attribute__ ( ( aligned ) );
  while ( ( rv = recv ( nfqfd_rest, buf, sizeof ( buf ), 0 ) ) && rv >= 0 ){
    nfq_handle_packet ( globalh_out_rest, buf, rv );
  }
}


void* thread_nfq_in ( void *ptr )
{
  ptr = 0;
//endless loop of receiving packets and calling a handler on each packet
  int rv;
  char buf[4096] __attribute__ ( ( aligned ) );
  while ( ( rv = recv ( nfqfd_input, buf, sizeof ( buf ), 0 ) ) && rv >= 0 ){
    nfq_handle_packet ( globalh_in, buf, rv );
  }
}


//split on a " "(space) delimiter and return chunks
vector<string> split_string(string input){
  vector<string> output;
  int pos = 0;
  string token;
  while (true){
    pos = input.find(" ");
    if (pos == string::npos){ //last element
      token = input.substr(0, input.length());
      output.push_back(token);
      break;
    }
    token = input.substr(0, pos);
    output.push_back(token);
    input.erase(0, pos + 1);
  }
  return output;
}


string get_sha256_hexdigest(string exe_path){
  unsigned char sha_bytearray[DIGEST_SIZE];
  memset(sha_bytearray, 0, DIGEST_SIZE);
  FILE *stream = fopen(exe_path.c_str(), "r");
  if (!stream) return "CANT_READ_EXE"; //TODO handle this error in the caller
  sha256_stream(stream, (void *)sha_bytearray);
  _fclose(stream);
  //convert binary sha to hexlified string
  char sha_cstring [DIGEST_SIZE*2+1];
  sha_cstring[DIGEST_SIZE*2] = 0;
  for(int j = 0; j < DIGEST_SIZE; j++)
  sprintf(&sha_cstring[2*j], "%02X", sha_bytearray[j]);
  return sha_cstring;
}


void error(const char *msg){
  perror(msg);
  exit(1);
}


void tcp_server_process_messages(int newsockfd) {
  int i,n;
  char buffer[256];
  string send_msg;    //request that was dispatched to the frontend
  string sent_path;
  string sent_pid;
  string sent_stime;
  bool bDataAvailable;
  while (true) {
    sleep(1);
    bDataAvailable = false;
    if (!requestQueue.empty()) {
      assert(requestQueue.size() == 1);
      vector<string> split_msg = split_string(requestQueue.front());
      send_msg = requestQueue.front();
      requestQueue.pop();
      sent_path= split_msg[1];
      sent_pid = split_msg[2];
      sent_stime = split_msg[3];
      bDataAvailable = true;
    }
    else if (!rulesListQueue.empty()) {
      send_msg = rulesListQueue.front();
      rulesListQueue.pop();
      bDataAvailable = true;
    }
    if (bDataAvailable){
      if (send(newsockfd, send_msg.c_str(), send_msg.length(), MSG_NOSIGNAL) < 0) {
        error("ERROR writing to socket. UNREGISTERing");
        _close(newsockfd);
        return;
      }
    }
    bzero(buffer,256);
    n = read(newsockfd,buffer,255);
    if (n < 0) continue; //no data

    vector<string> string_parts = split_string(string(buffer));
    string comm = string_parts[0];
    if (comm == "LIST"){
      _pthread_mutex_lock ( &dlist_mutex );
       vector<rule> rulescopy = rules;
       //TODO is this how we do deep copy of vector??
      _pthread_mutex_unlock ( &dlist_mutex );
      string reply = "RULES_LIST ";
      for(int i=0; i < rulescopy.size(); i++){
        string is_active = rulescopy[i].is_active ? "TRUE": "FALSE";
        reply += rulescopy[i].path + " " + rulescopy[i].pid + " " + rulescopy[i].perms + " "
            + is_active + " " + to_string(rulescopy[i].nfmark_out) + " CRLF ";
      }
      reply += " EOL ";
      n = write(newsockfd, reply.c_str(), reply.length());
      if (n < 0) {
        error("ERROR writing to socket. UNREGISTERing");
        _close(newsockfd);
        return;
      }
    }
    else if (comm == "DELETE"){ // comm path
      ruleslist_delete_all(string_parts.at(1));
    }
    else if (comm == "WRITE"){ //Not in use
      rulesfileWrite();
    }
    else if (comm == "ADD"){ //ADD path pid perms
      if (!awaiting_reply_from_fe) die();
      string path = string_parts[1];
      string pid = string_parts[2];
      string perms = string_parts[3];
      if (sent_path != path || sent_pid != pid) die();
      if (perms == "IGNORED") awaiting_reply_from_fe = false;
      else if (path == "KERNEL_PROCESS"){
        ruleslist_add(KERNEL_PROCESS, pid, perms, TRUE, "", 0, 0 ,TRUE);
      }
      else {
        string procpath = "/proc/" + sent_pid + "/exe";
        char exepathbuf[PATHSIZE];
        string sha;
        memset ( exepathbuf, 0, PATHSIZE );
        _readlink (procpath.c_str(), exepathbuf, PATHSIZE-1 );
        if (exepathbuf != sent_path){
          cout << "Frontend asked to add a process that is no longer running";
          awaiting_reply_from_fe = false;
          continue;
        }
        if (perms == "ALLOW_ALWAYS" || perms == "DENY_ALWAYS"){
          sha = get_sha256_hexdigest(sent_path.c_str());
        }
//TODO should move stime check to ruleslist_add
//         unsigned long long stime;
//         stime = starttimeGet(atoi(pid));
//         if ( sent_to_fe_struct.stime != stime ){
//           cout << "Red alert!!!Start times don't match";
//            throw "Red alert!!!Start times don't match";
//           awaiting_reply_from_fe = FALSE;
//         }
       //TODO SECURITY.Check that /proc/PID inode wasn't changed while we were shasumming and exesizing
       ruleslist_add(sent_path, sent_pid, perms, true, sha, atoi(sent_stime.c_str()), 0 ,TRUE);
       awaiting_reply_from_fe = false;
       requestQueue = queue<string>(); //clear the queue
       _pthread_mutex_lock ( &dlist_mutex );
       vector<rule> rulescopy = rules;
       _pthread_mutex_unlock ( &dlist_mutex );
       string reply = "RULES_LIST ";
       for(int i=0; i < rulescopy.size(); i++){
         string is_active = rulescopy[i].is_active ? "TRUE": "FALSE";
         reply += rulescopy[i].path + " " + rulescopy[i].pid + " " + rulescopy[i].perms + " "
             + is_active + " " + to_string(rulescopy[i].nfmark_out) + " CRLF ";
       }
       reply += " EOL ";
       n = send(newsockfd, reply.c_str(), reply.length(), MSG_NOSIGNAL);
       if (n < 0) {
         error("ERROR writing to socket. UNREGISTERing");
         _close(newsockfd);
         return;
       }
      }
    }
    else if (comm == "UNREGISTER"){
      _close(newsockfd);
      return;
    }
    else {cout << "unknown command ";}
  } //while (true)
}

void* thread_tcp_server ( void *port_ptr ) {
   int sockfd, newsockfd;
   struct sockaddr_in serv_addr, cli_addr;
   prctl(PR_SET_NAME,"tcp_server",0,0,0);
   socklen_t clilen;
   int portno = *(int *)port_ptr;
   free(port_ptr);

   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) error("ERROR opening socket");
   bzero((char *) &serv_addr, sizeof(serv_addr));
   printf("Using port: %d\n",portno);
   ofstream myfile("/tmp/commport");
   myfile << to_string(portno);
   myfile.close();
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) error("ERROR on binding");
   while (true) {
     listen(sockfd,1);
     clilen = sizeof(cli_addr);
     newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
     if (newsockfd < 0) {
       error("ERROR on accept");
       die();
     }
     if(fcntl(newsockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0) {
       printf ("Couldn't set socket to non-blocking");
       die();
     }
     tcp_server_process_messages(newsockfd);
     //tcp_server_process_messages returns when frontend unregisters
     //we can listen for a new frontend connection
   }
}


//scan procfs and remove/mark inactive in dlist those apps that are no longer running
void* thread_refresh ( void* ptr ){
  prctl(PR_SET_NAME,"refresh",0,0,0);
  ptr = 0;     //to prevent gcc warnings of unused variable
  char exe_path[PATHSIZE];
  while (true){
    _pthread_mutex_lock ( &dlist_mutex );
    for(int i=0; i < rules.size(); i++){
       if (!rules[i].is_active || rules[i].path == KERNEL_PROCESS) continue;
       string proc_pid_exe = "/proc/" + rules[i].pid + "/exe";
       memset ( exe_path, 0, PATHSIZE );
       //readlink doesn't fail if PID is running
       if ( readlink ( proc_pid_exe.c_str(), exe_path, PATHSIZE ) != -1 ) continue;
       if (rules[i].perms == ALLOW_ONCE || rules[i].perms == DENY_ONCE){
         ruleslist_delete_one ( rules[i].path, rules[i].pid );
         break;
       }
       //Only delete *ALWAYS rule if there is at least one more rule in dlist with the same PATH
       //If the rule is the only one in dlist with such PATH, simply toggle is_active flag
       if (rules[i].perms == ALLOW_ALWAYS || rules[i].perms == DENY_ALWAYS){
         bool bFoundAnotherOne = false;
         for(int j=0; j < rules.size(); j++){ //scan the whole dlist again
           if (j == i) continue; //Make sure we don't find our own rule :)
           bFoundAnotherOne = true;
           ruleslist_delete_one ( rules[i].path, rules[i].pid );
           rulesfileWrite();
           break;
         }
         if (bFoundAnotherOne) break; //out of the vector iteration
         //no PATH match, toggle is active flag
         rules[i].pid = "0";
         rules[i].is_active = false;
         //nfmarks will be used by the next instance of app
         rules[i].nfmark_in = NFMARKIN_BASE + nfmark_count;
         rules[i].nfmark_out = NFMARKOUT_BASE +  nfmark_count;
         nfmark_count++;
         if (fe_active_flag_get()){
           string message = "RULES_LIST ";
           for(int k=0; k < rules.size(); k++){
             string is_active = rules[k].is_active ? "TRUE": "FALSE";
             message += rules[k].path + " " + rules[k].pid + " " + rules[k].perms + " "
                 + is_active + " " + to_string(rules[k].nfmark_out) + " CRLF ";
           }
           message += " EOL ";
           rulesListQueue.push(message);
         }
         break;
       }
    } //for(int i=0; i < rules.size(); i++)
    _pthread_mutex_unlock ( &dlist_mutex );
    sleep ( REFRESH_INTERVAL );
  } //while (true)
}


void rules_load(){
  ifstream inputFile(rules_file->filename[0]);
  string line;
  int pos;
  while (getline(inputFile, line))
  {
    rule newrule;
    if ((pos = line.find(" ")) == string::npos) return; //empty rules file
    newrule.path = line.substr(0, pos);
    line.erase(0, pos + 1);
    if ((pos = line.find(" ")) == string::npos) die();
    newrule.perms = line.substr(0, pos);
    line.erase(0, pos + 1);
    newrule.sha = line.substr(0, line.length());
    newrule.pid = "0";
    newrule.is_active = false;
    newrule.stime = 0;
    newrule.first_instance = true;
    newrule.nfmark_out = 0;
    newrule.nfmark_in = 0;
    rules.push_back(newrule);
  }
  inputFile.close();
}


//iterate over rulescopy removing all rules which are not *ALWAYS
//or which are duplicates of other *ALWAYS rules with the same path
//this will leave us with rulescopy with unique *ALWAYS rules
void rulesfileWrite(){
  _pthread_mutex_lock ( &dlist_mutex );
  vector<rule> rulescopy = rules;
  //TODO is this how we copy the vector?
  _pthread_mutex_unlock ( &dlist_mutex );
  int i;
  for(i = 0; i < rulescopy.size(); i++){
    if (rulescopy[i].perms == ALLOW_ALWAYS || rulescopy[i].perms == DENY_ALWAYS) continue;
    //else
    rulescopy.erase(rulescopy.begin()+i);
    --i; //indexes shrunk by one, we need to revisit the same index on next iteration
  }
  //iterate again removing duplicate
  int j;
  for(i = 0; i < rulescopy.size(); i++){
    for(j = i+1; j < rulescopy.size(); j++){
      if (rulescopy[j].path != rulescopy[i].path) continue;
      //else
      rulescopy.erase(rulescopy.begin()+j);
      --j;
    }
  }
  //write rules
  string string_to_write;
  for(i = 0; i < rulescopy.size(); i++){
    string_to_write += rulescopy[i].path + " " + rulescopy[i].perms
                    + " " + rulescopy[i].sha + "\n";
  }
  ofstream myfile(rules_file->filename[0]);
  myfile << string_to_write;
  myfile.close();
}


//if another rule with this path is in dlist already, check if our process is fork()ed or a new instance
int path_find_in_ruleslist ( int &nfmark_out, const string path_in,
                             const string pid_in, unsigned long long stime_in, bool going_out){
  _pthread_mutex_lock ( &dlist_mutex );
  vector<rule> rulescopy = rules;
  //TODO is this the correct way to copy???
  _pthread_mutex_unlock ( &dlist_mutex );

  bool bDuplicateFound = false;
  int i;
  for(i = 0; i < rulescopy.size(); i++) {
    if (rulescopy[i].path == path_in) {
      bDuplicateFound = true;
      break;
    }
  }
  if (!bDuplicateFound) return PATH_IN_RULES_NOT_FOUND;
  if (!rulescopy[i].is_active){ //rule in dlist has been added from rulesfile and hasn't seen traffic yet.
    string sha = get_sha256_hexdigest(path_in.c_str());
    if (rulescopy[i].sha != sha)
      return SHA_DONT_MATCH;
    //find the rule in rulelist and update rule
    _pthread_mutex_lock ( &dlist_mutex );
    bool matchingRuleFound = false;
    for(int j = 0; j < rules.size(); j++) {
      if (! (rules[j].path == rulescopy[i].path && rules[j].sha == rulescopy[i].sha)) continue;
      matchingRuleFound = true;
      rules[j].pid = pid_in;
      rules[j].is_active = true;
      rules[j].stime = stime_in;
      rules[j].pidfdpath = "/proc/" + pid_in + "/fd/";
      DIR *dirstream = opendir(rules[j].pidfdpath.c_str());
      //if the app immediately terminated we may get NULL
      if (dirstream != NULL) rules[j].dirstream = dirstream;
      rules[j].nfmark_in = NFMARKIN_BASE + nfmark_count;
      rules[j].nfmark_out = NFMARKOUT_BASE +  nfmark_count;
      nfmark_count++;
      if (going_out) nfmark_out = rules[j].nfmark_out;
      else nfmark_out = rules[j].nfmark_in;
      if ((rules[j].sockets_cache = (long*)malloc(sizeof(long)*MAX_CACHE)) == NULL) perror("malloc");
      *rules[j].sockets_cache = MAGIC_NO;
      break;
    }
    if (!matchingRuleFound) die();
    _pthread_mutex_unlock ( &dlist_mutex );

    int retval;
    if (rulescopy[i].perms == ALLOW_ONCE || rulescopy[i].perms == ALLOW_ALWAYS) {
      retval = PATH_FOUND_IN_DLIST_ALLOW;}
    else if (rulescopy[i].perms == DENY_ONCE || rulescopy[i].perms == DENY_ALWAYS) {
      retval = PATH_FOUND_IN_DLIST_DENY;}
    else die(); //should never get here
    if (fe_active_flag_get()) {

      _pthread_mutex_lock ( &dlist_mutex );
      string message = "RULES_LIST ";
      for(int k=0; k < rules.size(); k++){
        string is_active = rules[k].is_active ? "TRUE": "FALSE";
        message += rules[k].path + " " + rules[k].pid + " " + rules[k].perms + " "
            + is_active + " " + to_string(rules[k].nfmark_out) + " CRLF ";
      }
      message += " EOL ";
      rulesListQueue.push(message);
      _pthread_mutex_unlock ( &dlist_mutex );

    }
    return retval;
  }
  else if (rulescopy[i].is_active){
    //determine if this is new instance or fork()d child
    // --------------------------
    // Here is how to determine if a process with the same PATH is either a new instance or a fork()ed process.
    //
    // 1. Get new process's(NP) PPID.(parent PID)
    // 2. Is there an entry in dlist with the same PATH as NP AND PID == PPID?
    // 3. If no then we have a new instance, go to step A1
    // 4. If yes, we have a fork()ed process, go to step B1
    //
    // A1. Are there any entries in dlist with the same PATH as NP AND *ALWAYS perms? If yes, then create new entry in dlist copy parent's perms and all other attributer over to NP and continue;
    // A2. If No, i.e. there either aren't any entries in dlist with the same PATH as NP OR there are entries with the same path as NP AND *ONCE perms, then query user.
    //
    // B1. Create new entry in dlist copy parent's perms and all other attributes over to NP and continue.
    // --------------------------

    //get new process's PPID
    string proc_stat_path = "/proc/" + pid_in + "/stat";
    FILE *stream1;
    if ( (stream1 = fopen ( proc_stat_path.c_str(), "r" ) ) == NULL ) return PROCFS_ERROR;
    char ppid[16];
    fscanf ( stream1, "%*s %*s %*s %s", ppid );
    _fclose ( stream1);

    //is it a fork()ed child? the "parent" above may not be the actual parent of this fork, e.g. there may be
    //two or three instances of an app running aka three "parents". We have to rescan dlist to ascertain
    for(int j = 0; j < rulescopy.size(); j++) {
      if ( ! (rulescopy[j].path == path_in && rulescopy[j].pid == ppid)) continue;
      //else we have a fork()ed child
      int retval;
      if (rulescopy[j].perms == ALLOW_ALWAYS || rulescopy[j].perms == ALLOW_ONCE) retval = FORKED_CHILD_ALLOW;
      else if (rulescopy[j].perms == DENY_ALWAYS || rulescopy[j].perms == DENY_ONCE) retval = FORKED_CHILD_DENY;
      unsigned long long stime;
      stime = starttimeGet ( atoi ( pid_in.c_str() ) );
      nfmark_out = ruleslist_add ( path_in, pid_in, rulescopy[j].perms, TRUE, rulescopy[j].sha,
                                       stime, 0, FALSE );
      if (fe_active_flag_get()) {
        _pthread_mutex_lock ( &dlist_mutex );
        string message = "RULES_LIST ";
        for(int k=0; k < rules.size(); k++){
          string is_active = rules[k].is_active ? "TRUE": "FALSE";
          message += rules[k].path + " " + rules[k].pid + " " + rules[k].perms + " "
              + is_active + " " + to_string(rules[k].nfmark_out) + " CRLF ";
        }
        message += " EOL ";
        rulesListQueue.push(message);
        _pthread_mutex_unlock ( &dlist_mutex );
      }

      return retval;
    }
    //we get here when we have a new instance, need to ascertain that app instantiated from
    //unmodified binary
    string sha = get_sha256_hexdigest(path_in.c_str());
    if (sha != rulescopy[i].sha ) { return SHA_DONT_MATCH; }
    // A1. Are there any entries in dlist with the same PATH as NP AND *ALWAYS perms? If yes, then create new entry in dlist copy parent's perms and all other attributes over to NP and continue;
    // A2. If No, i.e. there either aren't any entries in dlist with the same PATH as NP OR there are entries with the same path as NP AND *ONCE perms, then query user.
    bool bDuplicateFound = false;
    for(int k = 0; k < rulescopy.size(); k++) {
      if ( ! (rulescopy[k].path == path_in &&
              (rulescopy[k].perms == ALLOW_ALWAYS || rulescopy[k].perms == DENY_ALWAYS))) continue;
      //else
      bDuplicateFound = true;
      nfmark_out = ruleslist_add ( path_in, pid_in, rulescopy[i].perms, TRUE, rulescopy[i].sha, stime_in, 0 ,FALSE);
      if (fe_active_flag_get()) {

        _pthread_mutex_lock ( &dlist_mutex );
        string message = "RULES_LIST ";
        for(int k=0; k < rules.size(); k++){
          string is_active = rules[k].is_active ? "TRUE": "FALSE";
          message += rules[k].path + " " + rules[k].pid + " " + rules[k].perms + " "
              + is_active + " " + to_string(rules[k].nfmark_out) + " CRLF ";
        }
        message += " EOL ";
        rulesListQueue.push(message);
        _pthread_mutex_unlock ( &dlist_mutex );

      }
      if (rulescopy[k].perms == ALLOW_ALWAYS) return NEW_INSTANCE_ALLOW;
      else if (rulescopy[k].perms == DENY_ALWAYS) return NEW_INSTANCE_DENY;
    }
    if (!bDuplicateFound) return PATH_IN_RULES_NOT_FOUND;
  } //else if (rulescopy[i].is_active){
}


int socket_active_processes_search ( const long mysocket_in, string &m_path_out,
                                     string &m_pid_out, int  &nfmark_out){
  string path_dir;
  string path_file;
  DIR *m_dir;
  struct dirent *m_dirent;

  _pthread_mutex_lock ( &dlist_mutex );
  vector<rule> rulescopy = rules;
  _pthread_mutex_unlock ( &dlist_mutex );

  string find_socket = "socket:[" + to_string(mysocket_in) + "]";
  int i;
  for(i = 0; i < rulescopy.size(); i++) {
    if (!rulescopy[i].is_active || rulescopy[i].path == KERNEL_PROCESS) continue;
    path_dir = "/proc/" + rulescopy[i].pid + "/fd/";
    if ( ! ( m_dir = opendir ( path_dir.c_str() ) ) ) {
      //This condition can happen if process is still in the rules list,
      //has just exited and refresh_thread hasn't yet purged it out of the rules list
      continue;
    }
    while ( m_dirent = readdir ( m_dir ) ) {
      path_file = path_dir + m_dirent->d_name; //path2 contains /proc/PID/fd/1,2,3 etc. which are symlinks
      char socketbuf[32];
      int size = readlink (path_file.c_str(), socketbuf, SOCKETBUFSIZE ); //no trailing 0
      socketbuf[size] = 0;
      if (find_socket != socketbuf) continue;
      //else match found
      string procexepath = "/proc/" + rulescopy[i].pid + "/exe";
      char exepathbuf[PATHSIZE];
      size = readlink (procexepath.c_str(), exepathbuf, PATHSIZE ); //no trailing 0
      socketbuf[size] = 0;
      m_path_out = exepathbuf;
      m_pid_out = rulescopy[i].pid;
      _closedir ( m_dir );
      unsigned long long stime = starttimeGet ( atoi ( rulescopy[i].pid.c_str() ) );
      if ( rulescopy[i].stime != stime ) {
        printf ("SPOOFED_PID in %s %s %d", rulescopy[i].path.c_str(),  __FILE__, __LINE__ );
        return SPOOFED_PID;
      }
      if (rulescopy[i].perms == ALLOW_ONCE  || rulescopy[i].perms == ALLOW_ALWAYS) {
        nfmark_out = rulescopy[i].nfmark_out;
        return SOCKET_FOUND_IN_DLIST_ALLOW;
      }
      if (rulescopy[i].perms == DENY_ONCE || rulescopy[i].perms == DENY_ALWAYS) {
        return SOCKET_FOUND_IN_DLIST_DENY;
      }
    } //while ( m_dirent = readdir ( m_dir ) )
  } //for(i = 0; i < rulescopy.size(); i++)
  return SOCKET_ACTIVE_PROCESSES_NOT_FOUND;
}


int socket_procpidfd_search ( const long mysocket_in, string &m_path_out,
                              string &m_pid_out, unsigned long long &stime_out) {
  struct dirent *proc_dirent, *fd_dirent;
  DIR *proc_DIR, *fd_DIR;
  string fdpath;   // holds path to /proc/<pid>/fd/<number_of_inode_opened>
  // buffers to hold readlink()ed values of /proc/<pid>/exe and /proc/<pid>/fd/<inode>
  char exepathbuf[PATHSIZE];
  char socketbuf[SOCKETBUFSIZE];
  string find_socket = "socket:[" + to_string(mysocket_in) + "]";

  if ((proc_DIR = opendir("/proc")) == NULL) return SOCKET_NOT_FOUND_IN_PROCPIDFD;
  while (true){
    proc_dirent = readdir ( proc_DIR );
    if (proc_dirent == NULL) {
      _closedir ( proc_DIR );
      break;
    }
    if (! ((47 < proc_dirent->d_name[0]) && (proc_dirent->d_name[0] < 58))) continue; //only ASCII 1 thru 9 allowed
    string path = string("/proc/") + string(proc_dirent->d_name) + string("/fd");
    fd_DIR = opendir ( path.c_str() );
    if (fd_DIR == NULL ) continue; //process quit after readdir(proc_DIR) and path no longer exist
    while (true) {
      fd_dirent = readdir ( fd_DIR );
      if (fd_dirent == NULL ){
        _closedir ( fd_DIR );
        break;
      }
      //make sure theres no . in the path
      if ( fd_dirent->d_name[0] == 46 ) continue;
      fdpath = path + "/" + fd_dirent->d_name;
      int size= readlink (fdpath.c_str(), socketbuf, SOCKETBUFSIZE ); //no trailing 0
      socketbuf[size] = 0;
      if (find_socket != socketbuf) continue;
      //else we found our socket!!!!
      path = string("/proc/") + string(proc_dirent->d_name) + string("/exe");
      try {
        stime_out  = starttimeGet ( atoi ( proc_dirent->d_name ) );
        size = _readlink ( path.c_str(), exepathbuf, PATHSIZE - 1 );
      } catch (...){
        return SOCKET_NOT_FOUND_IN_PROCPIDFD;//the process exited as we were querying
      }
      exepathbuf[size] = 0;
      _closedir ( fd_DIR );
      _closedir ( proc_DIR );
      m_path_out = exepathbuf;
      m_pid_out = proc_dirent->d_name;
      return SOCKET_FOUND_IN_PROCPIDFD;
    }
  }
  return SOCKET_NOT_FOUND_IN_PROCPIDFD;
}


//if there are more than one entry in /proc/net/raw for icmp then it's impossible to tell which app is sending the packet
int icmp_check_only_one_socket ( long *socket )
{
  int loop = 0;
  int readbytes = 1;
  char socket_str[32];

  while ( 1 )
    {
      _lseek ( procnetrawfd, 206 + 110 * loop, SEEK_SET );
      readbytes = _read (procnetrawfd, socket_str, 8 );
      //in case there was icmp packet but no /proc/net/raw entry - report
      if ( ( loop == 0 ) && ( readbytes == 0 ) )
        {
          M_PRINTF ( MLOG_INFO, "ICMP packet without /proc/net/raw entry" );
          return ICMP_NO_ENTRY;
        }
      //if there are two lines in the file, we drop the packet
      if ( loop > 0 )
        {
          if ( readbytes == 0 ) break; //break while loop
          //else the are more than one line
          return ICMP_MORE_THAN_ONE_ENTRY;
        }
      int i;
      for ( i = 0; i < 32; ++i )
        {
	  if ( socket_str[i] == 32 )
            {
	      socket_str[i] = 0; // 0x20 space, see /proc/net/ucp
              break;
            }
        }
      *socket = atol ( socket_str );
      ++loop;
    }
  M_PRINTF ( MLOG_DEBUG, "(icmp)socket %ld", *socket );
  return ICMP_ONLY_ONE_ENTRY;
}


int inkernel_check_udp(const int port)
{
//The only way to distinguish kernel sockets is that they have inode=0 and uid=0
//But regular process's sockets sometimes also have inode=0 (I don't know why)
//+ root's sockets have uid == 0
//So we just assume that if inode==0 and uid==0 - it's a kernel socket

    int bytesread_udp,bytesread_udp6;
    char newline[2] = {'\n','\0'};
    char uid[2] = {'0','\0'};
    long socket_next;
    int port_next;
    char *token, *lasts;
    FILE *m_udpinfo, *m_udp6info;
    int m_udpinfo_fd, m_udp6info_fd;
    char m_udp_smallbuf[4096], m_udp6_smallbuf[4096];

    if ( ( m_udpinfo = fopen ( UDPINFO, "r" ) ) == NULL )
      {
	M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	exit (PROCFS_ERROR);
      }
    m_udpinfo_fd = fileno(m_udpinfo);

    memset(m_udp_smallbuf,0, 4096);
    while ((bytesread_udp = read(m_udpinfo_fd, m_udp_smallbuf, 4060)) > 0)
      {
	if (bytesread_udp == -1)
	  {
	    perror ("read");
	    return -1;
	  }
	token = strtok_r(m_udp_smallbuf, newline, &lasts); //skip the first line (column headers)
	while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
	  {
	    //take a line until EOF
	    sscanf(token, "%*s %*8s:%4X %*s %*s %*s %*s %*s %s %*s %ld", &port_next, uid, &socket_next);
      if (port_next != port ) continue;
	    else{
		if (socket_next != 0){
		    _fclose(m_udpinfo);
		    return SOCKET_CHANGED_FROM_ZERO;
		}
		else if (!strcmp (uid, "0")){
		    _fclose(m_udpinfo);
		    return INKERNEL_SOCKET_FOUND;
		}
		else{
		  _fclose(m_udpinfo);
		  return SOCKET_ZERO_BUT_UID_NOT_ZERO;
		}
	    }
	  }
      }
    _fclose(m_udpinfo);

//not found in /proc/net/udp, search in /proc/net/udp6

    if ( ( m_udp6info = fopen ( UDP6INFO, "r" ) ) == NULL )
      {
	M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	exit (PROCFS_ERROR);
      }
    m_udp6info_fd = fileno(m_udp6info);

    memset(m_udp6_smallbuf,0, 4096);
    while ((bytesread_udp6 = read(m_udp6info_fd, m_udp6_smallbuf, 4060)) > 0)
      {
	if (bytesread_udp6 == -1)
	  {
	    perror ("read");
	    return -1;
	  }
	token = strtok_r(m_udp6_smallbuf, newline, &lasts); //skip the first line (column headers)
	while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
	  {
	    //take a line until EOF
	    sscanf(token, "%*s %*32s:%4X %*s %*s %*s %*s %*s %s %*s %ld", &port_next, uid, &socket_next);
      if (port_next != port ) continue;
	    else{
		if (socket_next != 0){
		    _fclose(m_udp6info);
		    return SOCKET_CHANGED_FROM_ZERO;
		}
		else if (!strcmp (uid, "0")){
		    _fclose(m_udp6info);
		    return INKERNEL_SOCKET_FOUND;
		}
		else{
		  _fclose(m_udp6info);
		  return SOCKET_ZERO_BUT_UID_NOT_ZERO;
		}
	    }
	  }
      }
    _fclose(m_udp6info);
    return INKERNEL_SOCKET_NOT_FOUND;
 }


int inkernel_check_tcp(const int port)
{
//The only way to distinguish kernel sockets is that they have inode=0 and uid=0
//But regular process's sockets sometimes also have inode=0 (I don't know why)
//+ root's sockets have uid == 0
//So we just assume that if inode==0 and uid==0 - it's a kernel socket

    int bytesread_tcp,bytesread_tcp6;
    char newline[2] = {'\n','\0'};
    char uid[2] = {'0','\0'};
    long socket_next;
    int port_next;
    char *token, *lasts;
    FILE *m_tcpinfo, *m_tcp6info;
    int m_tcpinfo_fd, m_tcp6info_fd;
    char m_tcp_smallbuf[4096], m_tcp6_smallbuf[4096];

    if ( ( m_tcpinfo = fopen ( TCPINFO, "r" ) ) == NULL )
      {
	M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	exit (PROCFS_ERROR);
      }
    m_tcpinfo_fd = fileno(m_tcpinfo);

    memset(m_tcp_smallbuf,0, 4096);
    while ((bytesread_tcp = read(m_tcpinfo_fd, m_tcp_smallbuf, 4060)) > 0)
      {
	if (bytesread_tcp == -1)
	  {
	    perror ("read");
	    return -1;
	  }
	token = strtok_r(m_tcp_smallbuf, newline, &lasts); //skip the first line (column headers)
	while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
	  {
	    //take a line until EOF
	    sscanf(token, "%*s %*8s:%4X %*s %*s %*s %*s %*s %s %*s %ld", &port_next, uid, &socket_next);
      if (port_next != port ) continue;
	    else{
		if (socket_next != 0){
		    _fclose(m_tcpinfo);
		    return SOCKET_CHANGED_FROM_ZERO;
		}
		else if (!strcmp (uid, "0")){
		    _fclose(m_tcpinfo);
		    return INKERNEL_SOCKET_FOUND;
		}
		else{
		  _fclose(m_tcpinfo);
		  return SOCKET_ZERO_BUT_UID_NOT_ZERO;
		}
	    }
	  }
      }
    _fclose(m_tcpinfo);

//not found in /proc/net/tcp, search in /proc/net/tcp6

    if ( ( m_tcp6info = fopen ( TCP6INFO, "r" ) ) == NULL )
      {
	M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	exit (PROCFS_ERROR);
      }
    m_tcp6info_fd = fileno(m_tcp6info);

    memset(m_tcp6_smallbuf,0, 4096);
    while ((bytesread_tcp6 = read(m_tcp6info_fd, m_tcp6_smallbuf, 4060)) > 0)
      {
	if (bytesread_tcp6 == -1)
	  {
	    perror ("read");
	    return -1;
	  }
	token = strtok_r(m_tcp6_smallbuf, newline, &lasts); //skip the first line (column headers)
	while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
	  {
	    //take a line until EOF
	    sscanf(token, "%*s %*32s:%4X %*s %*s %*s %*s %*s %s %*s %ld", &port_next, uid, &socket_next);
      if (port_next != port ) continue;
	    else{
		if (socket_next != 0){
		    _fclose(m_tcp6info);
		    return SOCKET_CHANGED_FROM_ZERO;
		}
		else if (!strcmp (uid, "0")){
		    _fclose(m_tcp6info);
		    return INKERNEL_SOCKET_FOUND;
		}
		else{
		  _fclose(m_tcp6info);
		  return SOCKET_ZERO_BUT_UID_NOT_ZERO;
		}
	    }
	  }
      }
    _fclose(m_tcp6info);
    return INKERNEL_SOCKET_NOT_FOUND;
 }


//NEEDED BY THE TEST SUITE, don't comment out yet
//find in procfs which socket corresponds to source port
int port2socket_udp ( int *portint, int *socketint )
{
  char *udp_membuf, *udp6_membuf;
  char buffer[5];
  char procport[12];
  char socketstr[12];
  long m_socketint;
  int not_found_once=0;
  int bytesread_udp = 0;
  int bytesread_udp6 = 0;
  int i = 0;

  struct timespec timer,dummy;
  timer.tv_sec=0;
  timer.tv_nsec=1000000000/4;
  //convert portint to a hex string of 4 all-caps chars with leading zeroes if necessary
  char porthex[5];
  sprintf (porthex, "%04X", *portint );

  goto dont_fread;

do_fread:
  memset(udp_membuf,0, MEMBUF_SIZE);
  _fseek(udpinfo,0,SEEK_SET);
  errno = 0;
  if (bytesread_udp = fread(udp_membuf, sizeof(char), MEMBUF_SIZE , udpinfo))
    {
      if (errno != 0) perror("READERORRRRRRR");
    }
  M_PRINTF (MLOG_DEBUG2, "udp bytes read: %d\n", bytesread_udp);

  memset(udp6_membuf, 0, MEMBUF_SIZE);
  fseek(udp6info,0,SEEK_SET);
  errno = 0;
  if (bytesread_udp6 = fread(udp6_membuf, sizeof(char), MEMBUF_SIZE , udp6info))
    {
      if (errno != 0) perror("6READERORRRRRRR");
    }
  M_PRINTF (MLOG_DEBUG2, "udp6 bytes read: %d\n", bytesread_udp6);

dont_fread:
  ;
  char newline[2] = {'\n','\0'};
  char *token, *lasts;
  token = strtok_r(udp_membuf, newline, &lasts); //skip the first line (column headers)
  while ((token = strtok_r(NULL, newline, &lasts)) != NULL)  //take a line until EOF
    {
      sscanf(token, "%*s %*8s:%4s %*s %*s %*s %*s %*s %*s %*s %ld \n", buffer, &m_socketint);
      if (!strcmp (porthex, buffer))
        goto endloop;
    }
  // else EOF reached with no match, check if it was IPv6 socket

  token = strtok_r(udp6_membuf, newline, &lasts); //skip the first line (column headers)
  while ((token = strtok_r(NULL, newline, &lasts)) != NULL)  //take a line until EOF
    {
      sscanf(token, "%*s %*32s:%4s %*s %*s %*s %*s %*s %*s %*s %ld \n", buffer, &m_socketint);
      if (!strcmp (porthex, buffer))
        goto endloop;
    }

  //else EOF reached with no match, if it was 1st iteration then reread proc file
  if (not_found_once)
    {
      return SRCPORT_NOT_FOUND_IN_PROC;
    }
  //else
  nanosleep(&timer, &dummy);
  not_found_once=1;
  goto do_fread;

endloop:
  *socketint = m_socketint;
  if (*socketint == 0) return INKERNEL_SOCKET_FOUND;
  //else
  return 0;
}


//find in procfs which socket corresponds to source port
int  port2socket_tcp ( int *portint, int *socketint )
{
  char* tcp_membuf, *tcp6_membuf;
  char buffer[5];
  char procport[12];
  char socketstr[12];
  long m_socketint;
  int not_found_once=0;
  int bytesread_tcp = 0;
  int bytesread_tcp6 = 0;
  int i = 0;

  struct timespec timer,dummy;
  timer.tv_sec=0;
  timer.tv_nsec=1000000000/4;
  //convert portint to a hex string of 4 all-caps chars with leading zeroes if necessary
  char porthex[5];
  sprintf (porthex, "%04X", *portint );

  goto dont_fread;

do_fread:
  memset(tcp_membuf,0, MEMBUF_SIZE);
  _fseek(tcpinfo,0,SEEK_SET);
  errno = 0;
  if (bytesread_tcp = fread(tcp_membuf, sizeof(char), MEMBUF_SIZE , tcpinfo))
    {
      if (errno != 0) perror("fread tcpinfo");
    }
  M_PRINTF (MLOG_DEBUG2, "tcp bytes read: %d\n", bytesread_tcp);

  memset(tcp6_membuf, 0, MEMBUF_SIZE);
  _fseek(tcp6info,0,SEEK_SET);
  errno = 0;
  if (bytesread_tcp6 = fread(tcp6_membuf, sizeof(char), MEMBUF_SIZE , tcp6info))
    {
      if (errno != 0) perror("fread tcp6info");
    }
  M_PRINTF (MLOG_DEBUG2, "tcp6 bytes read: %d\n", bytesread_tcp6);

dont_fread:
  ;
  char newline[2] = {'\n','\0'};
  char *token, *lasts;
  token = strtok_r(tcp_membuf, newline, &lasts); //skip the first line (column headers)
  while ((token = strtok_r(NULL, newline, &lasts)) != NULL)  //take a line until EOF
    {
      sscanf(token, "%*s %*8s:%4s %*s %*s %*s %*s %*s %*s %*s %ld \n", buffer, &m_socketint);
      if (!strcmp (porthex, buffer))
        goto endloop;
    }
  // else EOF reached with no match, check if it was IPv6 socket

  token = strtok_r(tcp6_membuf, newline, &lasts); //skip the first line (column headers)
  while ((token = strtok_r(NULL, newline, &lasts)) != NULL)  //take a line until EOF
    {
      sscanf(token, "%*s %*32s:%4s %*s %*s %*s %*s %*s %*s %*s %ld \n", buffer,& m_socketint);
      if (!strcmp (porthex, buffer))
        goto endloop;
    }

  //else EOF reached with no match, if it was 1st iteration then reread proc file
  if (not_found_once)
    {
      return SRCPORT_NOT_FOUND_IN_PROC;
    }
  //else
  nanosleep(&timer, &dummy);
  not_found_once=1;
  goto do_fread;

endloop:
  *socketint = m_socketint;
  if (*socketint == 0) return INKERNEL_SOCKET_FOUND;
  //else
  return 0;
}


//Handler for TCP packets for INPUT NFQUEUE
int socket_handle_tcp_in ( const long socket_in, int &nfmark_out,
                           string &path_out, string &pid_out, unsigned long long &stime)
{
    int retval;
    retval = search_pid_and_socket_cache_in(socket_in, path_out, pid_out, nfmark_out);
    if (retval != SOCKETS_CACHE_NOT_FOUND)
    {
      M_PRINTF (MLOG_DEBUG2, "(cache)");
      return retval;
    }
    retval = socket_active_processes_search ( socket_in, path_out, pid_out, nfmark_out );
    if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND)
    {
      return retval;
    }
    retval = socket_procpidfd_search ( socket_in, path_out, pid_out, stime );
    if (retval == SOCKET_NOT_FOUND_IN_PROCPIDFD)
    {
      return retval;
    }
    else if (retval == SOCKET_FOUND_IN_PROCPIDFD)
    {
      retval = path_find_in_ruleslist ( nfmark_out, path_out, pid_out, stime, false);
      return retval;
    }
}


//Handler for TCP packets for OUTPUT NFQUEUE
int socket_handle_tcp_out ( const long socket_in, int &nfmark_out,
                            string &path_out, string &pid_out, unsigned long long &stime_out)
{
  int retval;
  retval = search_pid_and_socket_cache_out(socket_in, path_out, pid_out, nfmark_out);
  if (retval != SOCKETS_CACHE_NOT_FOUND){
      M_PRINTF (MLOG_DEBUG2, "(cache)");
      return retval;
  }
  retval = socket_active_processes_search ( socket_in, path_out, pid_out, nfmark_out );
  if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND ){
      return retval;
  }
  retval = socket_procpidfd_search ( socket_in, path_out, pid_out, stime_out );
  if (retval == SOCKET_NOT_FOUND_IN_PROCPIDFD){
    return retval;
  }
  else if (retval == SOCKET_FOUND_IN_PROCPIDFD){
    retval = path_find_in_ruleslist ( nfmark_out, path_out, pid_out, stime_out, true);
    return retval;
  }
}


//Handler for UDP packets
int socket_handle_udp_in (const long socket_in, int &nfmark_out,
                          string &path_out, string &pid, unsigned long long &stime) {
    int retval;
    retval = search_pid_and_socket_cache_in(socket_in, path_out, pid, nfmark_out);
    if (retval != SOCKETS_CACHE_NOT_FOUND)
    {
	M_PRINTF (MLOG_DEBUG2, "(cache)");
	return retval;
    }
    retval = socket_active_processes_search ( socket_in, path_out, pid, nfmark_out );
    if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND )
    {
	return retval;
    }
    retval = socket_procpidfd_search ( socket_in, path_out, pid, stime );
    if (retval == SOCKET_NOT_FOUND_IN_PROCPIDFD)
    {
      return retval;
    }
    else if (retval == SOCKET_FOUND_IN_PROCPIDFD)
    {
      retval = path_find_in_ruleslist ( nfmark_out, path_out, pid, stime, false);
      return retval;
    }
}


//Handler for UDP packets
int socket_handle_udp_out(const long socket_in, int &nfmark_out, string &path_out,
                          string &pid_out, unsigned long long &stime_out)
{
    int retval;
    retval = search_pid_and_socket_cache_out(socket_in, path_out, pid_out, nfmark_out);
    if (retval != SOCKETS_CACHE_NOT_FOUND)
    {
	M_PRINTF (MLOG_DEBUG2, "(cache)");
	return retval;
    }
    retval = socket_active_processes_search ( socket_in, path_out, pid_out, nfmark_out );
    if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND )
    {
      return retval;
    }
    retval = socket_procpidfd_search ( socket_in, path_out, pid_out, stime_out );
    if (retval == SOCKET_NOT_FOUND_IN_PROCPIDFD)
    {
      return retval;
    }
    else if (retval == SOCKET_FOUND_IN_PROCPIDFD)
    {
      retval = path_find_in_ruleslist ( nfmark_out, path_out, pid_out, stime_out, true);
      return retval;
    }
}


long is_tcp_port_in_cache (const int port)
{
  int i = 0;
  int retval;
  while (tcp_port_and_socket_cache[i*2] != (unsigned long)MAGIC_NO) {
    if (i >= (MEMBUF_SIZE / (sizeof(unsigned long)*2)) - 1) break;
    if (tcp_port_and_socket_cache[i*2] != (unsigned long)port) {
      i++;
      continue;
    }
    retval = tcp_port_and_socket_cache[i*2+1];
    return retval;
  }
  i = 0;
  while (tcp6_port_and_socket_cache[i*2] != (unsigned long)MAGIC_NO) {
    if (i >= (MEMBUF_SIZE / (sizeof(unsigned long)*2)) - 1) break;
    if (tcp6_port_and_socket_cache[i*2] != port) {
      i++;
      continue;
    }
    retval = tcp6_port_and_socket_cache[i*2+1];
    return retval;
  }
  //it wasn't found reinject it into the NFQUEUE again
  return -1;
}


long is_udp_port_in_cache (const int port)
{
  int i = 0;
  while (udp_port_and_socket_cache[i*2] != (unsigned long)MAGIC_NO)
    {
      if (i >= (MEMBUF_SIZE / (sizeof(unsigned long)*2)) - 1) break;
      if (udp_port_and_socket_cache[i*2] !=(unsigned long) port)
        {
          i++;
          continue;
        }
      else
        {
	  return udp_port_and_socket_cache[i*2+1];
        }
    }

  i = 0;
  while (udp6_port_and_socket_cache[i*2] != (unsigned long)MAGIC_NO)
    {
      if (i >= (MEMBUF_SIZE / (sizeof(unsigned long)*2)) - 1) break;
      if (udp6_port_and_socket_cache[i*2] != (unsigned long)port)
        {
          i++;
          continue;
        }
      else
        {
          int retval2;
	  retval2 = udp6_port_and_socket_cache[i*2+1];
          return retval2;
        }
    }
  //it wasn't found reinject it into the NFQUEUE again
  return -1;
}


void print_traffic_log(const int proto, const int direction, const char *ip, const int srcport,
		       const int dstport, const char *path, const char *pid, const int verdict)
{
  char m_logstring[PATHSIZE];
  if (direction == DIRECTION_IN)
    {
      strcpy(m_logstring,">");
      if (proto == PROTO_TCP)
        {
          strcat(m_logstring,"TCP ");
        }
      else if (proto == PROTO_UDP)
        {
          strcat (m_logstring, "UDP ");
        }
      else if (proto == PROTO_ICMP)
        {
          strcat (m_logstring, "ICMP ");
        }
      char port[8];
      sprintf (port,"%d",dstport);
      strcat (m_logstring, "dst ");
      strcat (m_logstring, port);
      strcat (m_logstring, " src ");
      strcat (m_logstring, ip);
      strcat (m_logstring,":");
      sprintf(port, "%d", srcport);
      strcat (m_logstring, port);
      strcat (m_logstring, " ");
    }
  else if (direction == DIRECTION_OUT)
    {
      strcpy(m_logstring,"<");
      if (proto == PROTO_TCP)
        {
          strcat(m_logstring,"TCP ");
        }
      else if (proto == PROTO_UDP)
        {
          strcat (m_logstring, "UDP ");
        }
      else if (proto == PROTO_ICMP)
        {
          strcat (m_logstring, "ICMP ");
        }
      char port[8];
      sprintf (port,"%d",srcport);
      strcat (m_logstring, "src ");
      strcat (m_logstring, port);
      strcat (m_logstring, " dst ");
      strcat (m_logstring, ip);
      strcat (m_logstring,":");
      sprintf(port, "%d", dstport);
      strcat (m_logstring, port);
      strcat (m_logstring, " ");
    }
  strcat (m_logstring, path);
  strcat (m_logstring, " ");
  strcat (m_logstring, pid);
  strcat (m_logstring, " ");

  switch ( verdict )
    {
    case SOCKET_FOUND_IN_DLIST_ALLOW:
    case PATH_FOUND_IN_DLIST_ALLOW:
    case NEW_INSTANCE_ALLOW:
    case FORKED_CHILD_ALLOW:
    case CACHE_TRIGGERED_ALLOW:
    case INKERNEL_RULE_ALLOW:

      strcat (m_logstring, "allow\n");
      break;

    case GLOBAL_RULE_ALLOW:
      strcat (m_logstring, "(global rule) allow\n");
      break;


    case CANT_READ_EXE:
      strcat (m_logstring, "(can't read executable file) drop\n");
      break;
    case SENT_TO_FRONTEND:
      strcat (m_logstring,  "(asking frontend) drop\n" );
      break;
    case SOCKET_FOUND_IN_DLIST_DENY:
    case PATH_FOUND_IN_DLIST_DENY:
    case NEW_INSTANCE_DENY:
    case FORKED_CHILD_DENY:
    case CACHE_TRIGGERED_DENY:
    case INKERNEL_RULE_DENY:
      strcat (m_logstring,  "deny\n" );
      break;
    case GLOBAL_RULE_DENY:
      strcat (m_logstring, "(global rule) deny \n");
      break;
    case SOCKET_NOT_FOUND_IN_PROCPIDFD:
      strcat (m_logstring,  "(no process associated with packet) drop\n" );
      break;
    case DSTPORT_NOT_FOUND_IN_PROC:
    case PORT_NOT_FOUND_IN_PROCNET:
      strcat (m_logstring,  "(no process associated with port) drop\n" );
      break;
    case FRONTEND_NOT_LAUNCHED:
      strcat (m_logstring, "(frontend not active) drop\n" );
      break;
    case FRONTEND_BUSY:
      strcat (m_logstring, "(frontend busy) drop\n" );
      break;
    case UNSUPPORTED_PROTOCOL:
      strcat (m_logstring, "(unsupported protocol) drop\n" );
      break;
    case ICMP_MORE_THAN_ONE_ENTRY:
      strcat (m_logstring, "More than one program is using icmp, dropping\n" );
      break;
    case ICMP_NO_ENTRY:
      strcat (m_logstring, "icmp packet received by there is no icmp entry in /proc. Very unusual. Please report\n" );
      break;
    case SHA_DONT_MATCH:
      strcat (m_logstring, "Red alert. Some app is trying to impersonate another\n" );
      break;
    case SPOOFED_PID:
      strcat (m_logstring, "Attempt to spoof PID detected\n" );
      break;
    case EXESIZE_DONT_MATCH:
      strcat (m_logstring, "Red alert. Executable's size don't match the records\n" );
      break;
    case EXE_HAS_BEEN_CHANGED:
      strcat (m_logstring, "While process was running, someone changed his binary file on disk. Definitely an attempt to compromise the firewall\n" );
      break;
    case SRCPORT_NOT_FOUND_IN_PROC:
      strcat (m_logstring, "(source port not found in procfs) drop\n" );
      break;
    case INKERNEL_SOCKET_NOT_FOUND:
      strcat (m_logstring, "(no process associated with socket) drop\n" );
      break;
    case INKERNEL_IPADDRESS_NOT_IN_DLIST:
      strcat (m_logstring, "(kernel process without a rule) drop\n" );
      break;
    case SOCKET_ZERO_BUT_UID_NOT_ZERO:
      strcat (m_logstring, "(socket==0 but uid!=0) drop\n" );
      break;
    case SOCKET_CHANGED_FROM_ZERO:
      strcat (m_logstring, "(socket changed from zero while we were scanning) drop\n" );
      break;
    case PROCFS_ERROR:
      strcat (m_logstring, "(Couldn't find /proc/<pid>/stat entry) drop\n" );
      break;
    default:
      strcat (m_logstring, "unknown verdict detected \n" );
      printf ("verdict No %d \n", verdict);
      break;
    }
  M_PRINTF(MLOG_TRAFFIC, "%s", m_logstring);
}


int socket_handle_icmp(int &nfmark_out, string &path_out,
                       string &pid_out, unsigned long long &stime_out)
{
  int retval;
  long socket;
  retval = icmp_check_only_one_socket ( &socket );
  if (retval != ICMP_ONLY_ONE_ENTRY) {return retval;}
  retval = socket_active_processes_search (socket, path_out, pid_out, nfmark_out );
  if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND) {return retval;}
  retval = socket_procpidfd_search (socket, path_out, pid_out, stime_out);
  if (retval != SOCKET_FOUND_IN_PROCPIDFD) {return retval;}
  retval = path_find_in_ruleslist (nfmark_out, path_out, pid_out, stime_out, true);
  return retval;
}


int inkernel_get_verdict(const char *ipaddr_in, int &nfmark_out) {
  _pthread_mutex_lock ( &dlist_mutex );
  for(int i = 0; i < rules.size(); i++){
    if (rules[i].path == KERNEL_PROCESS) continue;
    if (rules[i].pid != ipaddr_in) continue;
    if (rules[i].perms == ALLOW_ALWAYS || rules[i].perms == ALLOW_ONCE) {
      rules[i].is_active = true;
      nfmark_out = rules[i].nfmark_out;
      _pthread_mutex_unlock(&dlist_mutex);
      return INKERNEL_RULE_ALLOW;
    }
    else if (rules[i].perms == DENY_ALWAYS || rules[i].perms == DENY_ONCE) {
      _pthread_mutex_unlock(&dlist_mutex);
      return INKERNEL_RULE_DENY;
    }
  }
  _pthread_mutex_unlock(&dlist_mutex);
  return INKERNEL_IPADDRESS_NOT_IN_DLIST;
}


int  nfq_handle_gid ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata )
{
  struct iphdr *ip;
  int id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
  if ( ph ) id = ntohl ( ph->packet_id );
  nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );

  char daddr[INET_ADDRSTRLEN], saddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip->saddr), saddr, INET_ADDRSTRLEN);

  //source and destination ports in host and net byte order
  int sport_netbo, dport_netbo, sport_hostbo, dport_hostbo;
  int proto;
  int verdict;
  switch ( ip->protocol )
    {
    case IPPROTO_TCP:
      proto = PROTO_TCP;
      // ihl is IP header length in 32bit words, multiply a word by 4 to get length in bytes
      struct tcphdr *tcp;
      tcp = ( struct tcphdr* ) ( (char*)ip + ( 4 * ip->ihl ) );
      sport_netbo = tcp->source;
      dport_netbo = tcp->dest;
      sport_hostbo = ntohs ( tcp->source );
      dport_hostbo = ntohs ( tcp->dest );
      break;

    case IPPROTO_UDP:
      proto = PROTO_UDP;
      struct udphdr *udp;
      udp = ( struct udphdr * ) ( (char*)ip + ( 4 * ip->ihl ) );
      sport_netbo = udp->source;
      dport_netbo = udp->dest;
      sport_hostbo = ntohs ( udp->source );
      dport_hostbo = ntohs ( udp->dest );
      break;

    default:
      M_PRINTF ( MLOG_INFO, "IN unsupported protocol detected No. %d (lookup in /usr/include/netinet/in.h)\n", ip->protocol );
      M_PRINTF ( MLOG_INFO, "see FAQ on how to securely let this protocol use the internet \n" );
    }

  verdict = GID_MATCH_ALLOW;
  //print_traffic_log(proto, DIRECTION_IN, saddr, sport_hostbo, dport_hostbo, path, pid, verdict);
  if (verdict == GID_MATCH_ALLOW)
    {
      printf ("allowed gid match /n");
      nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );

      nfct_set_attr_u32(ct_in, ATTR_ORIG_IPV4_DST, ip->daddr);
      nfct_set_attr_u32(ct_in, ATTR_ORIG_IPV4_SRC, ip->saddr);
      nfct_set_attr_u8 (ct_in, ATTR_L4PROTO, ip->protocol);
      nfct_set_attr_u8 (ct_in, ATTR_L3PROTO, AF_INET);
      nfct_set_attr_u16(ct_in, ATTR_PORT_SRC, sport_netbo);
      nfct_set_attr_u16(ct_in, ATTR_PORT_DST, dport_netbo) ;

	nfmark_to_set_in = 22222;
      //EBUSY returned, when there's too much activity in conntrack. Requery the packet
      while (nfct_query(setmark_handle_in, NFCT_Q_GET, ct_in) == -1)
	{
	  if (errno == EBUSY)
	    {
	      M_PRINTF ( MLOG_INFO, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	      break;
	    }
	  if (errno == EILSEQ)
	    {
	      M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	      break;
	    }
	  else
	    {
	      M_PRINTF ( MLOG_INFO, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	      break;
	    }
	}
      return 0;
    }
  else if (verdict == GID_MATCH_DENY)
  {
      printf ("denied gid match /n");
      denied_traffic_add(DIRECTION_IN, 22222, ip->tot_len );
      nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
      return 0;
  }
  else
  {
  nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
  return 0;
  }
}


int  nfq_handle_in ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata )
{
  _pthread_mutex_lock(&lastpacket_mutex);
  gettimeofday(&lastpacket, NULL);
  _pthread_mutex_unlock(&lastpacket_mutex);

  struct iphdr *ip;
  int id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
  if ( ph ) id = ntohl ( ph->packet_id );
  nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );

  char daddr[INET_ADDRSTRLEN], saddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip->saddr), saddr, INET_ADDRSTRLEN);

  int verdict;
  //source and destination ports in host and net byte order
  int sport_netbo, dport_netbo, sport_hostbo, dport_hostbo;
  string path, pid;
  unsigned long long starttime;
  int proto;
  long socket;
  int nfmark = 0; //if the mark changes to non-zero, assign it to the global var nfmark
  switch ( ip->protocol )
    {
    case IPPROTO_TCP:
      proto = PROTO_TCP;
      // ihl is IP header length in 32bit words, multiply a word by 4 to get length in bytes
      struct tcphdr *tcp;
      tcp = ( struct tcphdr* ) ( (char*)ip + ( 4 * ip->ihl ) );
      sport_netbo = tcp->source;
      dport_netbo = tcp->dest;
      sport_hostbo = ntohs ( tcp->source );
      dport_hostbo = ntohs ( tcp->dest );

      if ((socket = is_tcp_port_in_cache(sport_hostbo)) == -1) //not found in cache
        {
	  //No need to rebuild the cache b/c likelihood is very high that port is not there
	  verdict = DSTPORT_NOT_FOUND_IN_PROC;
	  break;
        }
      if (socket == 0){
    verdict = inkernel_check_tcp(dport_hostbo);
	  if (verdict == INKERNEL_SOCKET_FOUND) {
        verdict = inkernel_get_verdict(saddr, nfmark);
	  }
	  else break;
      }
      else{
      //fe_was_busy_in = awaiting_reply_from_fe? TRUE: FALSE;
      verdict = socket_handle_tcp_in (socket, nfmark, path, pid, starttime );
      }
    //verdict = global_rules_filter(DIRECTION_IN, PROTO_TCP, dport_hostbo, verdict);

    if (verdict == PATH_IN_RULES_NOT_FOUND){
      //if (fe_was_busy_in) {verdict = FRONTEND_BUSY;}
      if (! fe_active_flag_get()) {verdict = FRONTEND_NOT_LAUNCHED;}
      else if (fe_active_flag_get()) {
        requestQueue.push("REQUEST " + string(path) + " " + string(pid) + " " + to_string(starttime) +
                        " " + string(saddr) + " " + to_string(sport_hostbo) + " " +
                      to_string(dport_hostbo) + " EOL ");
        verdict =SENT_TO_FRONTEND;
      }
    }

    break;

    case IPPROTO_UDP:
      proto = PROTO_UDP;
      struct udphdr *udp;
      udp = ( struct udphdr * ) ( (char*)ip + ( 4 * ip->ihl ) );
      sport_netbo = udp->source;
      dport_netbo = udp->dest;
      sport_hostbo = ntohs ( udp->source );
      dport_hostbo = ntohs ( udp->dest );

      if ((socket = is_udp_port_in_cache(dport_hostbo)) == -1) //not found in cache
        {
	  verdict = DSTPORT_NOT_FOUND_IN_PROC;
	  break;
	}
      if (socket == 0){
    verdict = inkernel_check_tcp(dport_hostbo);
	  if (verdict == INKERNEL_SOCKET_FOUND) {
        verdict = inkernel_get_verdict(daddr, nfmark);
	  }
	  else break;
      }
      else{
      //fe_was_busy_in = awaiting_reply_from_fe? true: false;
      verdict = socket_handle_udp_in (socket, nfmark, path, pid, starttime );
      }
    //verdict = global_rules_filter(DIRECTION_IN, PROTO_UDP, dport_hostbo, verdict);

    if (verdict == PATH_IN_RULES_NOT_FOUND){
      if (fe_active_flag_get()) {
        requestQueue.push("REQUEST " + string(path) + " " + string(pid) + " " + to_string(starttime) +
                        " " + string(saddr) + " " + to_string(sport_hostbo) + " " +
                      to_string(dport_hostbo) + " EOL ");
        verdict =SENT_TO_FRONTEND;
      }
      if (! fe_active_flag_get()) {verdict = FRONTEND_NOT_LAUNCHED;}
    }
    break;

/* Receiving incoming icmp connections should be done on the kernel level
    case IPPROTO_ICMP:
      M_PRINTF ( MLOG_TRAFFIC, ">ICMP src %s ", saddr);
      fe_was_busy_in = awaiting_reply_from_fe? TRUE: FALSE;
      if ((verdict = packet_handle_icmp (&nfmark_to_set_in, path, pid, &starttime )) == GOTO_NEXT_STEP)
        {
          if (fe_was_busy_in)
            {
              verdict = FRONTEND_BUSY;
              break;
            }
	  else verdict = fe_active_flag_get() ? fe_ask_in(path,pid,&starttime, saddr, sport_hostbo, dport_hostbo) : FRONTEND_NOT_LAUNCHED;
        }
      break;
 */
    default:
      M_PRINTF ( MLOG_INFO, "IN unsupported protocol detected No. %d (lookup in /usr/include/netinet/in.h)\n", ip->protocol );
      M_PRINTF ( MLOG_INFO, "see FAQ on how to securely let this protocol use the internet \n" );
      verdict = UNSUPPORTED_PROTOCOL;
    }

  print_traffic_log(proto, DIRECTION_IN, saddr, sport_hostbo, dport_hostbo,
                    path.c_str(), pid.c_str(), verdict);
  if (nfmark != 0) nfmark_to_set_in = nfmark;
  if (verdict < ALLOW_VERDICT_MAX)
    {
      nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );

      nfct_set_attr_u32(ct_in, ATTR_ORIG_IPV4_DST, ip->daddr);
      nfct_set_attr_u32(ct_in, ATTR_ORIG_IPV4_SRC, ip->saddr);
      nfct_set_attr_u8 (ct_in, ATTR_L4PROTO, ip->protocol);
      nfct_set_attr_u8 (ct_in, ATTR_L3PROTO, AF_INET);
      nfct_set_attr_u16(ct_in, ATTR_PORT_SRC, sport_netbo);
      nfct_set_attr_u16(ct_in, ATTR_PORT_DST, dport_netbo) ;

      //EBUSY returned, when there's too much activity in conntrack. Requery the packet
      while (nfct_query(setmark_handle_in, NFCT_Q_GET, ct_in) == -1)
        {
          if (errno == EBUSY)
            {
              M_PRINTF ( MLOG_INFO, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	      break;
            }
          if (errno == EILSEQ)
            {
              M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	      break;
            }
          else
            {
              M_PRINTF ( MLOG_INFO, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
              break;
            }
        }
      return 0;
    }
  else if (verdict < DENY_VERDICT_MAX)
  {
      denied_traffic_add(DIRECTION_IN, nfmark_to_set_in, ip->tot_len );
      nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
      return 0;
  }
  else
  {
  nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
  return 0;
  }
}


int  nfq_handle_out_rest ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata )
{
  _pthread_mutex_lock(&lastpacket_mutex);
  gettimeofday(&lastpacket, NULL);
  _pthread_mutex_unlock(&lastpacket_mutex);

  struct iphdr *ip;
  u_int32_t id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
  if ( !ph )
    {
      printf ("ph == NULL, should never happen, please report");
      return 0;
    }
  id = ntohl ( ph->packet_id );
  nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );
  char daddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
  int verdict;
  string path,pid;
  unsigned long long stime;
  switch (ip->protocol)
    {
    case IPPROTO_ICMP:
      //fe_was_busy_out = awaiting_reply_from_fe? TRUE: FALSE;
      verdict = socket_handle_icmp (nfmark_to_set_out_icmp, path, pid, stime );
//      if (verdict  == PATH_IN_DLIST_NOT_FOUND){
//        if (fe_was_busy_out){
//          verdict = FRONTEND_BUSY;
//          break;
//        }
//        else {
//          if (fe_active_flag_get()){
//            int zero = 0;
//            verdict = fe_ask_out(path,pid,&stime, daddr, &zero, &zero);
//          }
//          else { verdict = FRONTEND_NOT_LAUNCHED;}
//        }
//      }
      break;
    default:
      M_PRINTF ( MLOG_INFO, "OUT unsupported protocol detected No. %d (lookup in /usr/include/netinet/in.h)\n", ip->protocol );
      M_PRINTF ( MLOG_INFO, "see FAQ on how to securely let this protocol use the internet \n" );
      nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
      return 0;
    }


  print_traffic_log(PROTO_ICMP, DIRECTION_OUT, daddr, 0, 0, path.c_str(), pid.c_str(), verdict);
  if (verdict < ALLOW_VERDICT_MAX)
    {
      nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
      return 0;

//Fix assigning icmp mark when Netfilter devs reply to my mailing list post
      nfct_set_attr_u32(ct_out_icmp, ATTR_ORIG_IPV4_DST, ip->daddr);
      nfct_set_attr_u32(ct_out_icmp, ATTR_ORIG_IPV4_SRC, ip->saddr);
      nfct_set_attr_u8 (ct_out_icmp, ATTR_L4PROTO, ip->protocol);
      nfct_set_attr_u8 (ct_out_icmp, ATTR_L3PROTO, AF_INET);
      // nfct_set_attr_u16(ct_out_icmp, ATTR_PORT_SRC, sport_netbyteorder);
      // nfct_set_attr_u16(ct_out_icmp, ATTR_PORT_DST, dport_netbyteorder) ;

      //EBUSY returned, when there's too much activity in conntrack. Requery the packet
      while (nfct_query(setmark_handle_out_icmp, NFCT_Q_GET, ct_out_icmp) == -1)
        {
          if (errno == EBUSY)
            {
              M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	      break;
            }
          if (errno == EILSEQ)
            {
              M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	      break;
            }
          else
            {
              M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
              break;
            }
        }


    }
  //else if verdict > ALLOW_VERDICT_MAX
  nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
  return 0;
}

int  nfq_handle_out_udp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfad, void *mdata ) {
  _pthread_mutex_lock(&lastpacket_mutex);
  gettimeofday(&lastpacket, NULL);
  _pthread_mutex_unlock(&lastpacket_mutex);

  struct iphdr *ip;
  u_int32_t id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
  if ( !ph )
    {
      printf ("ph == NULL, should never happen, please report");
      return 0;
    }
  id = ntohl ( ph->packet_id );
  nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );
  char daddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
  int verdict;
  u_int16_t sport_netbyteorder, dport_netbyteorder;
  string path, pid;
  unsigned long long starttime;
  int nfmark;

  struct udphdr *udp;
  udp = ( struct udphdr * ) ( (char*)ip + ( 4 * ip->ihl ) );
  sport_netbyteorder = udp->source;
  dport_netbyteorder = udp->dest;
  int srcudp = ntohs ( udp->source );
  int dstudp = ntohs ( udp->dest );

  unsigned long socket_found;
  if ((socket_found = is_udp_port_in_cache(srcudp)) == -1) //not found in cache
    {
      struct timespec timer,dummy;
      timer.tv_sec=0;
      timer.tv_nsec=1000000000/2;
      nanosleep(&timer, &dummy);

      if (build_port_and_socket_cache(socket_found, srcudp, CACHE_UDP) == 0)
      {
          if (build_port_and_socket_cache(socket_found, srcudp, CACHE_UDP6) == 0)
          {
            //the packet has no inode associated with it
            verdict = PORT_NOT_FOUND_IN_PROCNET;
            goto execute_verdict;
          }
      }
    }

  if (socket_found == 0){
    verdict = inkernel_check_udp(srcudp);
    if (verdict == INKERNEL_SOCKET_FOUND) {
      verdict = inkernel_get_verdict(daddr, nfmark);
    }
    else {goto execute_verdict;}
  }
  else{
  //remember f/e's state before we process
  //fe_was_busy_out = awaiting_reply_from_fe? true: false;
  verdict = socket_handle_udp_out (socket_found, nfmark, path, pid, starttime);
  }
  //verdict = global_rules_filter(DIRECTION_OUT, PROTO_TCP, dstudp, verdict);

  if (verdict == PATH_IN_RULES_NOT_FOUND){
    //if (fe_was_busy_out){verdict = FRONTEND_BUSY;}
    if (! fe_active_flag_get()) {verdict = FRONTEND_NOT_LAUNCHED;}
    else if (fe_active_flag_get()) {
      requestQueue.push("REQUEST " + path + " " + pid + " " + to_string(starttime) +
                      " " + string(daddr) + " " + to_string(srcudp) + " " +
                    to_string(dstudp) + " EOL ");
      verdict = SENT_TO_FRONTEND;
    }
  }

  execute_verdict:
  print_traffic_log(PROTO_UDP, DIRECTION_OUT, daddr, srcudp, dstudp,
                    path.c_str(), pid.c_str(), verdict);

  if (nfmark != 0) nfmark_to_set_out_udp =nfmark;

  if (verdict < ALLOW_VERDICT_MAX)
    {
      nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );

      nfct_set_attr_u32(ct_out_udp, ATTR_ORIG_IPV4_DST, ip->daddr);
      nfct_set_attr_u32(ct_out_udp, ATTR_ORIG_IPV4_SRC, ip->saddr);
      nfct_set_attr_u8 (ct_out_udp, ATTR_L4PROTO, ip->protocol);
      nfct_set_attr_u8 (ct_out_udp, ATTR_L3PROTO, AF_INET);
      nfct_set_attr_u16(ct_out_udp, ATTR_PORT_SRC, sport_netbyteorder);
      nfct_set_attr_u16(ct_out_udp, ATTR_PORT_DST, dport_netbyteorder) ;

      //EBUSY returned, when there's too much activity in conntrack. Requery the packet
      while (nfct_query(setmark_handle_out_udp, NFCT_Q_GET, ct_out_udp) == -1)
        {
          if (errno == EBUSY)
            {
              M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	      break;
            }
          if (errno == EILSEQ)
            {
              M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	      break;
            }
          else
            {
              M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
              break;
            }
        }

      return 0;
    }
  else if (verdict < DENY_VERDICT_MAX)
  {
      denied_traffic_add(DIRECTION_OUT, nfmark_to_set_out_udp, ip->tot_len );
      nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
      return 0;
  }
  else
  {
  nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
  return 0;
  }
}


int send_request (const string path, const string pid, const string starttime,
             const string daddr, const string srctcp, const string dsttcp) {
  requestQueue.push("REQUEST " + path + " " + pid + " " + starttime +
                  " " + daddr + " " + srctcp + " " + dsttcp + " EOL ");
  return SENT_TO_FRONTEND;
}



int nfq_handle_out_tcp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfad, void *mdata ) {
  _pthread_mutex_lock(&lastpacket_mutex);
  gettimeofday(&lastpacket, NULL);
  _pthread_mutex_unlock(&lastpacket_mutex);

  struct iphdr *ip;
  u_int32_t id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
  if (!ph) { die("ph == NULL, should never happen, please report"); }
  id = ntohl ( ph->packet_id );
  nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );
  char daddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
  int verdict;
  u_int16_t sport_netbyteorder, dport_netbyteorder;
  string path,pid;
  unsigned long long starttime;
  int nfmark;

  cout << "nfq_handle_out_tcp triggered " << "daddr is " << daddr << "\n";

  // ihl field is IP header length in 32-bit words, multiply by 4 to get length in bytes
  struct tcphdr *tcp;
  tcp = ( struct tcphdr* ) ((char*)ip + ( 4 * ip->ihl ) );
  sport_netbyteorder = tcp->source;
  dport_netbyteorder = tcp->dest;
  int srctcp = ntohs ( tcp->source );
  int dsttcp = ntohs ( tcp->dest );

  unsigned long socket_found;
  if ((socket_found = is_tcp_port_in_cache(srctcp)) == -1) {
    cout << "socket not found in cache \n";
    //not found in cache
    if (build_port_and_socket_cache(socket_found, srctcp, CACHE_TCP) == 0) {
      if (build_port_and_socket_cache(socket_found, srctcp, CACHE_TCP6) == 0) {
        //the packet has no inode associated with it
        verdict = PORT_NOT_FOUND_IN_PROCNET;
        goto execute_verdict;
      }
	  }
  }
  assert (socket_found >= 0);
  if (socket_found == 0){
    verdict = inkernel_check_tcp(srctcp);
    if (verdict == INKERNEL_SOCKET_FOUND) {
      verdict = inkernel_get_verdict(daddr, nfmark);
    }
    else { goto execute_verdict; }
  }
  else {
    fe_was_busy_out = awaiting_reply_from_fe;
    verdict = socket_handle_tcp_out ( socket_found, nfmark, path, pid, starttime );
  }
  if (verdict == PATH_IN_RULES_NOT_FOUND){
    if (! fe_active_flag_get()) {verdict = FRONTEND_NOT_LAUNCHED; }
    else if (fe_was_busy_out) { verdict = FRONTEND_BUSY; }
    else if (awaiting_reply_from_fe) { verdict = FRONTEND_BUSY; }
    else {
      awaiting_reply_from_fe = true;
      //frontend is both active and was not busy when we started socket_handle_tcp_out
      //There was a small window when we were inside socket_handle_tcp_out
      //for the frontend to respond. So, we double-check that the path
      //we are about to query was not added to the rules during that small window
      verdict = path_find_in_ruleslist (nfmark, path, pid, starttime, true);
      if (verdict == PATH_IN_RULES_NOT_FOUND) {
        verdict = send_request(path, pid, to_string(starttime), string(daddr),
                             to_string(srctcp), to_string(dsttcp));
      }
    }
  }
execute_verdict:
  print_traffic_log(PROTO_TCP, DIRECTION_OUT, daddr, srctcp, dsttcp,
                    path.c_str(), pid.c_str(), verdict);

  if (nfmark != 0) nfmark_to_set_out_tcp = nfmark;

  if (verdict < ALLOW_VERDICT_MAX) {
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );

    nfct_set_attr_u32(ct_out_tcp, ATTR_ORIG_IPV4_DST, ip->daddr);
    nfct_set_attr_u32(ct_out_tcp, ATTR_ORIG_IPV4_SRC, ip->saddr);
    nfct_set_attr_u8 (ct_out_tcp, ATTR_L4PROTO, ip->protocol);
    nfct_set_attr_u8 (ct_out_tcp, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u16(ct_out_tcp, ATTR_PORT_SRC, sport_netbyteorder);
    nfct_set_attr_u16(ct_out_tcp, ATTR_PORT_DST, dport_netbyteorder) ;

    //EBUSY returned, when there's too much activity in conntrack. Requery the packet
    while (nfct_query(setmark_handle_out_tcp, NFCT_Q_GET, ct_out_tcp) == -1) {
      if (errno == EBUSY) {
          M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
          break;
      }
      if (errno == EILSEQ) {
          M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
          break;
      }
      else{
          M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
          break;
      }
    }
    return 0;
  } //if (verdict < ALLOW_VERDICT_MAX)
  else if (verdict < DENY_VERDICT_MAX) {
    denied_traffic_add(DIRECTION_OUT, nfmark_to_set_out_tcp, ip->tot_len );
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
    return 0;
  }
  else{
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
    return 0;
  }
}


void init_log()
{

  if ( !strcmp ( logging_facility->sval[0], "file" ) )
    {
//         if (log_info->ival) {
//             if ((fileloginfofd = fopen(log_file->filename[0], "w")) == 0) perror("fopen");
//         }
//         if (log_traffic->ival) {
//             if ((filelogtrafficfd = fopen(log_file->filename[0], "w")) == 0) perror("fopen");
//         }
//         if (log_debug->ival) {
//             if ((filelogdebugfd = fopen(log_file->filename[0], "w")) == 0) perror("fopen");
//         };

//all chennels log to the same file, if need be the commented section above can be used to specify separate files
      fileloginfo_stream = _fopen (log_file->filename[0], "w" );
      filelogtraffic_stream = fileloginfo_stream;
      filelogdebug_stream = fileloginfo_stream;
      m_printf = &m_printf_file;
      return;
    }
  else if ( !strcmp ( logging_facility->sval[0], "stdout" ) )
    {
      m_printf = &m_printf_stdout;
      return;
    }
#ifndef WITHOUT_SYSLOG
  else if ( !strcmp ( logging_facility->sval[0], "syslog" ) )
    {
      openlog ( "lpfw", 0, 0 );
      m_printf = &m_printf_syslog;
    }
#endif
}


void pidfile_check(){
  string pid_str;
  int pid_int;
  fstream pidfile;
  pidfile.open(pid_file->filename[0]);
  if (pidfile.is_open()) {  //file exists
    getline(pidfile, pid_str);
    pidfile.close();
    pid_int = atoi(pid_str.c_str());
    if (pid_int > 0 && (kill(pid_int,0)== 0)){//PID is running
      ifstream comm_path(string("/proc/") + pid_str + string("/comm"));
      string exe_name;
      getline(comm_path, exe_name);
      if (exe_name == "lpfw" && ( pid_t ) pid_int != getpid()){
        cout << "lpfw is already running\n";
        exit(1);
      }
    }
  }
  //else if pidfile doesn't exist/contains dead PID, create/truncate it and write our pid into it
  pidfile.open(pid_file->filename[0], ios_base::out | ios_base::trunc);
  pidfile << to_string((int)getpid());
  pidfile.close();
}


void SIGTERM_handler ( int signal )
{
  _remove ( pid_file->filename[0] );
  //release netfilter_queue resources
  _nfq_close ( globalh_out_tcp );
  _nfq_close ( globalh_out_udp );
  printf ("In sigterm handler");
  //remove iptables  rules
  _system ("iptables -F");
}

/*command line parsing contributed by Ramon Fried*/
int parse_command_line(int argc, char* argv[])
{
  // if the parsing of the arguments was unsuccessful
  int nerrors;

  // Define argument table structs
  logging_facility = arg_str0 ( NULL, "logging-facility",
#ifndef WITHOUT_SYSLOG
				"<file>,<stdout>,<syslog>"
#else
				"<file>,<stdout>"
#endif
				, "Divert logging to..." );
  rules_file = arg_file0 ( NULL, "rules-file", "<path to file>", "Rules output file" );
  pid_file = arg_file0 ( NULL, "pid-file", "<path to file>", "PID output file" );
  log_file = arg_file0 ( NULL, "log-file", "<path to file>", "Log output file" );
  allow_rule = arg_file0 ( NULL, "addrule", "<path to executable>", "Add executable to rulesfile as ALLOW ALWAYS" );


#ifndef WITHOUT_SYSVIPC
  cli_path = arg_file0 ( NULL, "cli-path", "<path to file>", "Path to CLI frontend" );
  pygui_path = arg_file0 ( NULL, "pygui-path", "<path to file>", "Path to Python-based GUI frontend" );
#endif

  log_info = arg_int0 ( NULL, "log-info", "<1/0 for yes/no>", "Info messages logging" );
  log_traffic = arg_int0 ( NULL, "log-traffic", "<1/0 for yes/no>", "Traffic logging" );
  log_debug = arg_int0 ( NULL, "log-debug", "<1/0 for yes/no>", "Debug messages logging" );
  test = arg_lit0 ( NULL, "test", "Run unit test" );

  struct arg_lit *help = arg_lit0 ( NULL, "help", "Display help screen" );
  struct arg_lit *version = arg_lit0 ( NULL, "version", "Display the current version" );
  struct arg_end *end = arg_end ( 30 );
  void *argtable[] = {logging_facility, rules_file, pid_file, log_file, cli_path,
      pygui_path, log_info, log_traffic, log_debug, allow_rule, help, version,
      test, end};

  // Set default values
  char *stdout_pointer;
  stdout_pointer = (char*)_malloc(strlen("stdout")+1);
  strcpy (stdout_pointer, "stdout");
  logging_facility->sval[0] = stdout_pointer;

  char *rulesfile_pointer;
  rulesfile_pointer = (char*)_malloc(strlen(RULESFILE)+1);
  strcpy (rulesfile_pointer, RULESFILE);
  rules_file->filename[0] = rulesfile_pointer;

  char *pidfile_pointer;
  pidfile_pointer = (char*)_malloc(strlen(PIDFILE)+1);
  strcpy (pidfile_pointer, PIDFILE);
  pid_file->filename[0] = pidfile_pointer;

  char *lpfw_logfile_pointer;
  lpfw_logfile_pointer = (char*)_malloc(strlen(LPFW_LOGFILE)+1);
  strcpy (lpfw_logfile_pointer, LPFW_LOGFILE);
  log_file->filename[0] = lpfw_logfile_pointer;

  cli_path->filename[0] = CLI_FILE;
  pygui_path->filename[0] = GUI_FILE;

  * ( log_info->ival ) = 1;
  * ( log_traffic->ival ) = 1;
#ifdef DEBUG
  * ( log_debug->ival ) = 1;
#else
  * ( log_debug->ival ) = 0;
#endif

  if ( arg_nullcheck ( argtable ) != 0 )
    {
      printf ( "Error: insufficient memory\n" );
      exit(0);
    }

  nerrors = arg_parse ( argc, argv, argtable );

  if ( nerrors == 0 )
    {
      if ( help->count == 1 )
	{
	  printf ( "Leopard Flower:\n Syntax and help:\n" );
	  arg_print_glossary ( stdout, argtable, "%-43s %s\n" );
	  exit (0);
	}
      else if ( version->count == 1 )
	{
	  printf ( "%s\n", VERSION );
	  exit (0);
	}
      else if (allow_rule->count == 1)
      {
	add_to_rulesfile(allow_rule->filename[0]);
	exit(0);
      }
      else if (test->count == 1) //log traffic to a separate file
      {
  char *file_pointer = (char*)malloc(strlen("file")+1);
	strcpy (file_pointer, "file");
	logging_facility->sval[0] = file_pointer;

	 * ( log_traffic->ival ) = 1;

  char *log_file_pointer = (char *)malloc(strlen(TEST_TRAFFIC_LOG)+1);
	strcpy (log_file_pointer, TEST_TRAFFIC_LOG);
	log_file->filename[0] = TEST_TRAFFIC_LOG;
      }
    }
  else if ( nerrors > 0 )
    {
      arg_print_errors ( stdout, end, "Leopard Flower" );
      printf ( "Leopard Flower:\n Syntax and help:\n" );
      arg_print_glossary ( stdout, argtable, "%-43s %s\n" );
      exit (1);
    }

  // Free memory - don't do this cause args needed later on
  //  arg_freetable(argtable, sizeof (argtable) / sizeof (argtable[0]));
}

//add an executable (from command line) with ALLOW ALWAYS permissions
void add_to_rulesfile(const char *exefile_path)
{
  FILE *rulesfile_stream;
  string sha = get_sha256_hexdigest(exefile_path);
  //Open rules file and add to the bottom of it
  if ( access ( rules_file->filename[0], F_OK ) == -1 ){
    printf ( "CONFIG doesnt exist..creating" );
    rulesfile_stream = _fopen (rules_file->filename[0], "w");
  }
  else {rulesfile_stream = _fopen (rules_file->filename[0], "a");}

  _fseek (rulesfile_stream, 0, SEEK_END);
  _fputs (exefile_path, rulesfile_stream);
  _fputc ('\n', rulesfile_stream);
  _fputs (ALLOW_ALWAYS, rulesfile_stream);
  _fputc ('\n', rulesfile_stream);
  _fputs (sha.c_str(), rulesfile_stream);
  _fputc ('\n', rulesfile_stream);
  _fclose (rulesfile_stream);
}


void capabilities_setup()
{
  cap_flag_value_t value;
  cap_t cap_current = _cap_get_proc();

  cap_get_flag(cap_current, CAP_SYS_PTRACE, CAP_PERMITTED, &value);
  if (value == CAP_CLEAR)
    {
      printf ("CAP_SYS_PTRACE is not permitted \n");
      exit(0);
    }
  cap_get_flag(cap_current, CAP_NET_ADMIN, CAP_PERMITTED, &value);
  if (value == CAP_CLEAR)
    {
      printf ("CAP_NET_ADMIN is not permitted \n");
      exit(0);
    }
  cap_get_flag(cap_current, CAP_DAC_READ_SEARCH, CAP_PERMITTED, &value);
  if (value == CAP_CLEAR)
    {
      printf ("CAP_DAC_READ_SEARCH is not permitted \n");
      exit(0);
    }
  cap_get_flag(cap_current, CAP_SETUID, CAP_PERMITTED, &value);
  if (value == CAP_CLEAR)
    {
      printf ("CAP_SETUID is not permitted \n");
      exit(0);
    }
  cap_get_flag(cap_current, CAP_SETGID, CAP_PERMITTED, &value);
  if (value == CAP_CLEAR)
    {
      printf ("CAP_SETGID is not permitted \n");
      exit(0);
    }
  cap_get_flag(cap_current, CAP_CHOWN, CAP_PERMITTED, &value);
  if (value == CAP_CLEAR)
    {
      printf ("CAP_CHOWN is not permitted \n");
      exit(0);
    }
  cap_get_flag(cap_current, CAP_FSETID, CAP_PERMITTED, &value);
  if (value == CAP_CLEAR)
    {
      printf ("CAP_FSETID is not permitted \n");
      exit(0);
    }
  cap_get_flag(cap_current, CAP_KILL, CAP_PERMITTED, &value);
  if (value == CAP_CLEAR)
    {
      printf ("CAP_KILL is not permitted \n");
      exit(0);
    }

  _cap_clear(cap_current);
  const cap_value_t caps_list[] = {CAP_SYS_PTRACE, CAP_NET_ADMIN, CAP_DAC_READ_SEARCH, CAP_SETUID, CAP_SETGID, CAP_CHOWN, CAP_FSETID, CAP_KILL};
  _cap_set_flag(cap_current, (cap_flag_t)CAP_PERMITTED, 8, caps_list, (cap_flag_value_t)CAP_SET);
  _cap_set_proc(cap_current);

#ifdef DEBUG
  cap_t cap;
  cap = _cap_get_proc();
  printf("Running with capabilities: %s\n", cap_to_text(cap, NULL));
  _cap_free(cap);
#endif
}

void setgid_lpfwuser()
{
  gid_t lpfwuser_gid;
  //First we need to create/(check existence of) lpfwuser group and add ourselves to it
  errno = 0;
  struct group *m_group;
  m_group = getgrnam("lpfwuser");
  if (!m_group)
    {
      if (errno == 0)
	{
	  printf("lpfwuser group does not exist, creating...\n");
	  if (system("groupadd lpfwuser") == -1)
	    {
	      printf("error in system(groupadd)\n");
	      return;
	    }
	  //get group id again after group creation
	  errno = 0;
	  m_group = getgrnam("lpfwuser");
	  if(!m_group)
	    {
	      if (errno == 0)
		{
		  printf ("lpfwuser group still doesn't exist even though we've just created it");
		}
	      else
		{
		  perror ("getgrnam");
		}
	    }
	  lpfwuser_gid = m_group->gr_gid;
	}
      else
	{
	  printf("Error in getgrnam\n");
	  perror ("getgrnam");
	}
      return;
    }
  //when debugging, we add user who launches frontend to lpfwuser group, hence disable this check
#ifndef DEBUG
  if (!(m_group->gr_mem[0] == NULL))
    {
      printf ("lpfwuser group contains users. This group should not contain any users. This is a security issue. Please remove all user from that group and restart application. Exitting\n");
      exit(0);
    }
#endif
  lpfwuser_gid = m_group->gr_gid;

  capabilities_modify(CAP_SETGID, CAP_EFFECTIVE, CAP_SET);

  //setgid and immediately remove CAP_SETGID from both perm. and eff. sets
  if (setgid(lpfwuser_gid) == -1)
    {
      printf("setgid: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
      return;
    }

  capabilities_modify(CAP_SETGID, CAP_EFFECTIVE, CAP_CLEAR);
  capabilities_modify(CAP_SETGID, CAP_PERMITTED, CAP_CLEAR);
}

void setuid_root()
{
  capabilities_modify(CAP_SETUID, CAP_EFFECTIVE, CAP_SET);

  //setuid and immediately remove CAP_SETUID from both perm. and eff. sets
  if (setuid(0) == -1)
    {
      perror ("setuid ");
      return;
    }
  //we still neet to setuid in fe_reg_thread so leave this CAP in permitted set
  //cap_set_flag(cap_current,  CAP_PERMITTED, 1, caps_list, CAP_CLEAR);
  capabilities_modify(CAP_SETUID, CAP_EFFECTIVE, CAP_CLEAR);
}

void setup_signal_handlers()
{
    //install SIGTERM handler
    struct sigaction sa;
    sa.sa_handler = SIGTERM_handler;
    sigemptyset ( &sa.sa_mask );
    //if ( sigaction ( SIGTERM, &sa, NULL ) == -1 ){perror ( "sigaction" );}

}


//check periodically if iptables rules were changed by another process
void* iptables_check_thread (void *ptr)
{
  prctl(PR_SET_NAME,"iptables check",0,0,0);
  struct stat mstat;
  int fd_output, fd_input, fd_newoutput, fd_newinput;
  char *addr_output, *addr_input, *addr_newoutput, *addr_newinput;
  int size_output, size_input, size_newoutput, size_newinput;
  char save_output[MAX_LINE_LENGTH] = "iptables -L OUTPUT > ";
  char save_input[MAX_LINE_LENGTH] = "iptables -L INPUT >";
  strcat (save_output, SAVE_IPTABLES_OUTPUT_FILE);
  strcat (save_input, SAVE_IPTABLES_INPUT_FILE);

  //commit to memory the contents of the files
  fd_output = _open(SAVE_IPTABLES_OUTPUT_FILE, O_RDONLY);
  _stat (SAVE_IPTABLES_OUTPUT_FILE , &mstat);
  size_output = mstat.st_size;
  addr_output = (char *)_mmap ((void*)NULL, size_output, PROT_READ, MAP_PRIVATE, fd_output, 0);
  _close (fd_output);

  fd_input = _open(SAVE_IPTABLES_INPUT_FILE, O_RDONLY);
  _stat (SAVE_IPTABLES_INPUT_FILE , &mstat);
  size_input = mstat.st_size;
  addr_input = (char *)_mmap ((void*)NULL, size_input, PROT_READ, MAP_PRIVATE, fd_input, 0);
  _close (fd_input);

  while (1)
  {
    sleep(3);
    _system (save_output);
    _system (save_input);

    fd_newoutput = _open(SAVE_IPTABLES_OUTPUT_FILE, O_RDONLY);
    _stat (SAVE_IPTABLES_OUTPUT_FILE , &mstat);
    size_newoutput = mstat.st_size;
    addr_newoutput = (char *)_mmap ((void*)NULL, size_newoutput, PROT_READ, MAP_PRIVATE, fd_newoutput, 0);
    _close (fd_newoutput);

    fd_newinput = _open(SAVE_IPTABLES_INPUT_FILE, O_RDONLY);
    _stat (SAVE_IPTABLES_INPUT_FILE , &mstat);
    size_newinput = mstat.st_size;
    addr_newinput = (char *)_mmap ((void*)NULL, size_newinput, PROT_READ, MAP_PRIVATE, fd_newinput, 0);
    _close (fd_newinput);

    int i,j;
    if (size_output != size_newoutput) goto alarm;
    if (size_input != size_newinput) goto alarm;
    if (i = memcmp(addr_output, addr_newoutput, size_output)) goto alarm;
    if (j = memcmp(addr_input, addr_newinput, size_input)) goto alarm;

    _munmap (addr_newoutput, size_newoutput);
    _munmap (addr_newinput, size_newinput);
  }
  alarm:
  printf ("IPTABLES RULES CHANGE DETECTED\n");
  printf ("Leopard Flower (LF) has detected that some other process has changed\n");
  printf ("iptables rules. Applications like Firestarter and NetworkManager\n");
  printf ("are known to change iptables rules. Since LF relies heavily on iptables,\n");
  printf ("most likely LF will not work correctly until it is restarted.\n");
  printf ("It is advised that you terminate LF.\n");
}

void init_iptables()
{
  pthread_t iptables_check;
  char save_output[MAX_LINE_LENGTH] = "iptables -L OUTPUT > ";
  char save_input[MAX_LINE_LENGTH] = "iptables -L INPUT >";

  _system ("iptables -F INPUT");
  _system ("iptables -F OUTPUT");
  string gid_match = ""; //not in use in normal (non-testing) mode
  if (test->count == 1) { gid_match= "-m owner --gid-owner lpfwtest"; }
  _system (string("iptables -I OUTPUT 1 -m state --state NEW " +
                  gid_match + " -j NFQUEUE --queue-num 11223").c_str());
  _system (string("iptables -I OUTPUT 1 -p tcp -m state --state NEW " +
                  gid_match + " -j NFQUEUE --queue-num 11220").c_str());
  _system (string("iptables -I OUTPUT 1 -p udp -m state --state NEW " +
                  gid_match + " -j NFQUEUE --queue-num 11222").c_str());
  //owner match doesn't work with INPUT hooks
  _system ("iptables -I INPUT 1 -m state --state NEW -j NFQUEUE --queue-num 11221");
  _system ("iptables -I OUTPUT 1 -d localhost -j ACCEPT");
  _system ("iptables -I INPUT 1 -d localhost -j ACCEPT");

  //save and start checking if iptables rules altered
  strcat (save_output, SAVE_IPTABLES_OUTPUT_FILE);
  strcat (save_input, SAVE_IPTABLES_INPUT_FILE);
  _system (save_output);
  _system (save_input);
  _pthread_create ( &iptables_check, (pthread_attr_t *)NULL, iptables_check_thread, (void *)NULL);
}

void init_nfq_handlers()
{
  struct nfq_q_handle * globalqh_tcp, * globalqh_udp, * globalqh_rest, * globalqh_input, * globalqh_gid;
  //-----------------Register OUT TCP queue handler-------------
  globalh_out_tcp = _nfq_open();
  _nfq_unbind_pf (globalh_out_tcp, AF_INET );
  _nfq_bind_pf (globalh_out_tcp, AF_INET );
  globalqh_tcp = _nfq_create_queue (globalh_out_tcp, NFQNUM_OUTPUT_TCP,
                                    &nfq_handle_out_tcp, (void*)NULL );
  //copy only 40 bytes of packet to userspace - just to extract tcp source field
  _nfq_set_mode (globalqh_tcp, NFQNL_COPY_PACKET, 40 );
  _nfq_set_queue_maxlen (globalqh_tcp, 200 );
  nfqfd_tcp = nfq_fd ( globalh_out_tcp);
  M_PRINTF ( MLOG_DEBUG, "nfqueue handler registered\n" );
  //--------Done registering------------------

  //-----------------Register OUT UDP queue handler-------------
  globalh_out_udp = _nfq_open();
  _nfq_unbind_pf (globalh_out_udp, AF_INET );
  _nfq_bind_pf (globalh_out_udp, AF_INET );
  globalqh_udp = _nfq_create_queue (globalh_out_udp, NFQNUM_OUTPUT_UDP,
                    &nfq_handle_out_udp, (void*)NULL );
  //copy only 40 bytes of packet to userspace - just to extract tcp source field
  _nfq_set_mode (globalqh_udp, NFQNL_COPY_PACKET, 40 );
  _nfq_set_queue_maxlen (globalqh_udp, 200 );
  nfqfd_udp = nfq_fd ( globalh_out_udp);
  M_PRINTF ( MLOG_DEBUG, "nfqueue handler registered\n" );
    //--------Done registering------------------

  //-----------------Register OUT REST queue handler-------------
  globalh_out_rest = _nfq_open();
  _nfq_unbind_pf (globalh_out_rest, AF_INET );
  _nfq_bind_pf (globalh_out_rest, AF_INET );
  globalqh_rest = _nfq_create_queue (globalh_out_rest, NFQNUM_OUTPUT_REST,
                    &nfq_handle_out_rest, (void*)NULL );
  //copy only 40 bytes of packet to userspace - just to extract tcp source field
  _nfq_set_mode (globalqh_rest, NFQNL_COPY_PACKET, 40 );
  _nfq_set_queue_maxlen (globalqh_rest, 200 );
  nfqfd_rest = nfq_fd ( globalh_out_rest);
  M_PRINTF ( MLOG_DEBUG, "nfqueue handler registered\n" );
    //--------Done registering------------------

  //-----------------Register IN queue handler-------------
  globalh_in = _nfq_open();
  _nfq_unbind_pf (globalh_in, AF_INET );
  _nfq_bind_pf (globalh_in, AF_INET );
  globalqh_input = _nfq_create_queue (globalh_in, NFQNUM_INPUT,
                    &nfq_handle_in, (void*)NULL );
  //copy only 40 bytes of packet to userspace - just to extract tcp source field
  _nfq_set_mode (globalqh_input, NFQNL_COPY_PACKET, 40 );
  _nfq_set_queue_maxlen (globalqh_input, 30 );
  nfqfd_input = nfq_fd ( globalh_in);
  M_PRINTF ( MLOG_DEBUG, "nfqueue handler registered\n" );
    //--------Done registering------------------
}


void open_proc_net_files()
{
  tcpinfo = _fopen (TCPINFO, "r");
  tcp6info = _fopen (TCP6INFO, "r");
  udpinfo = _fopen (UDPINFO, "r");
  udp6info = _fopen (UDP6INFO, "r");

  procnetrawfd = _open ("/proc/net/raw", O_RDONLY );
  tcpinfo_fd = _fileno(tcpinfo);
  tcp6info_fd = _fileno(tcp6info);
  udpinfo_fd = _fileno(udpinfo);
  udp6info_fd = _fileno(udp6info);
}

void chown_and_setgid_frontend()
{
    char system_call_string[PATHSIZE];

    //TODO check if we really need those 2 caps, maybe _CHOWN is enough.
    capabilities_modify(CAP_CHOWN, CAP_EFFECTIVE, CAP_SET);
    capabilities_modify(CAP_FSETID, CAP_EFFECTIVE, CAP_SET);
    capabilities_modify(CAP_DAC_READ_SEARCH, CAP_EFFECTIVE, CAP_SET);

    strcpy (system_call_string, "chown :lpfwuser ");
    strncat (system_call_string, cli_path->filename[0], PATHSIZE-20);
    _system (system_call_string);

    strcpy (system_call_string, "chmod g+s ");
    strncat (system_call_string, cli_path->filename[0], PATHSIZE-20);
    _system (system_call_string);

    strcpy (system_call_string, "chown :lpfwuser ");
    strncat (system_call_string, pygui_path->filename[0], PATHSIZE-20);
    _system (system_call_string);

    strcpy (system_call_string, "chmod g+s ");
    strncat (system_call_string, pygui_path->filename[0], PATHSIZE-20);
    _system (system_call_string);

    capabilities_modify(CAP_CHOWN, CAP_EFFECTIVE, CAP_CLEAR);
    capabilities_modify(CAP_CHOWN, CAP_PERMITTED, CAP_CLEAR);
    capabilities_modify(CAP_FSETID, CAP_EFFECTIVE, CAP_CLEAR);
    capabilities_modify(CAP_FSETID, CAP_PERMITTED, CAP_CLEAR);
}

int main ( int argc, char *argv[] )
{
  struct rlimit core_limit;
  core_limit.rlim_cur = RLIM_INFINITY;
  core_limit.rlim_max = RLIM_INFINITY;
  if(setrlimit(RLIMIT_CORE, &core_limit) < 0){
  printf("setrlimit: %s\nWarning: core dumps may be truncated or non-existant\n", strerror(errno));}

  if (argc == 2 && ( !strcmp(argv[1], "--help") || !strcmp(argv[1], "--version"))){
      parse_command_line(argc, argv);
      return 0;
  }

  capabilities_setup();
  setuid_root();
  setgid_lpfwuser();
  if (prctl(PR_SET_DUMPABLE, 1) == -1){ perror("prctl SET_DUMPABLE"); }
  setup_signal_handlers();

  parse_command_line(argc, argv);
  init_log();
  pidfile_check();
  capabilities_modify(CAP_NET_ADMIN, CAP_EFFECTIVE, CAP_SET);
  init_conntrack();
  init_iptables();

  capabilities_modify(CAP_DAC_READ_SEARCH, CAP_EFFECTIVE, CAP_SET);
  capabilities_modify(CAP_SYS_PTRACE, CAP_EFFECTIVE, CAP_SET);

  init_nfq_handlers();
  if (test->count != 1) {
    rules_load();
  }
  open_proc_net_files();

  _pthread_create ( &refresh_thr, (pthread_attr_t *)NULL, thread_refresh, (void *)NULL );
  _pthread_create ( &cache_build_thr, (pthread_attr_t *)NULL, thread_build_pid_and_socket_cache, (void *)NULL);
  _pthread_create ( &ct_dump_thr, (pthread_attr_t *)NULL, thread_ct_dump, (void *)NULL );
  _pthread_create ( &ct_destroy_hook_thr, (pthread_attr_t *)NULL, thread_ct_destroy, (void *)NULL);
  _pthread_create ( &ct_delete_nfmark_thr, (pthread_attr_t *)NULL, thread_ct_delete_mark, (void *)NULL);

  _pthread_create ( &nfq_in_thr, (pthread_attr_t *)NULL, thread_nfq_in, (void *)NULL);
  _pthread_create ( &nfq_out_udp_thr, (pthread_attr_t *)NULL, thread_nfq_out_udp, (void *)NULL);
  _pthread_create ( &nfq_out_rest_thr, (pthread_attr_t *)NULL, thread_nfq_out_rest, (void *)NULL);
  //generate a random port here, so that it could be passed into test thread in testing mode
  //the testing thread starts a frontend which connects to this port
  int port;
  srand (time(NULL));
  do { port = rand() % 65535;} while (port < 1025);
  int * port_ptr_for_tcp_server = (int *)malloc(sizeof(port));
  int * port_ptr_for_test_thread = (int *)malloc(sizeof(port));
  *port_ptr_for_tcp_server = port;
  *port_ptr_for_test_thread = port;
  _pthread_create ( &tcp_server_thr, (pthread_attr_t *)NULL, thread_tcp_server,
                    (void *)port_ptr_for_tcp_server);
  if (test->count == 1) {
    _pthread_create ( &test_thr, (pthread_attr_t *)NULL, thread_test,
                      (void *)port_ptr_for_test_thread);
  }

  //endless loop of receiving packets and calling a handler on each packet
  int rv;
  char buf[4096] __attribute__ ( ( aligned ) );
  while ( ( rv = recv ( nfqfd_tcp, buf, sizeof ( buf ), 0 ) ) && rv >= 0 )
    {
      nfq_handle_packet ( globalh_out_tcp, buf, rv );
    }
}
