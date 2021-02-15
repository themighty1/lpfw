#include <algorithm>
#include <arpa/inet.h> //for ntohl()
#include <assert.h>
#include <ctype.h> // for toupper
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <grp.h>
#include <dirent.h>
#include <iomanip>
#include <ios>
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
#include "sha256/sha256.h"
#include "base64.h"

using namespace std;

queue<string> rulesListQueue;
queue<string> requestQueue;

//should be available globally to call nfq_close from sigterm handler
struct nfq_handle *globalh_out, *globalh_in;

//command line arguments available globally
struct arg_str *logging_facility;
struct arg_file *rules_file, *pid_file, *log_file, *allow_rule;
struct arg_int *log_info, *log_traffic, *log_debug;
struct arg_lit *test;
//Paths of various frontends kept track of in order to chown&chmod them
struct arg_file *cli_path, *gui_path, *pygui_path;

FILE *fileloginfo_stream, *filelogtraffic_stream, *filelogdebug_stream;

vector<rule> rules; //each rule contains path,permission,hash

//pointer to the actual logging function
int ( *m_printf ) ( const int loglevel, const char *logstring );

//mutex to protect ruleslist
pthread_mutex_t rules_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_t refresh_thr, nfq_out_thr, nfq_in_thr, cache_build_thr, tcp_server_thr, test_thr;

//flag which shows whether frontend is running
bool bFrontendActive = false;
pthread_mutex_t fe_active_flag_mutex = PTHREAD_MUTEX_INITIALIZER;

//mutexed string which threads use for logging
pthread_mutex_t logstring_mutex = PTHREAD_MUTEX_INITIALIZER;
char logstring[PATHSIZE];

FILE *tcpinfo, *tcp6info, *udpinfo, *udp6info;
int tcpinfo_fd, tcp6info_fd, udpinfo_fd, udp6info_fd, procnetrawfd;

//track time when last packet was seen to put to sleep some threads when there is no traffic
struct timeval lastpacket = {0};
pthread_mutex_t lastpacket_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t tcp_port_and_socket_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t udp_port_and_socket_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

//for debug purposed - how many times read() was called
int tcp_stats, udp_stats;
//cache that holds correlation of ports<-->sockets from various /proc/net/* files
int tcp_port_and_socket_cache[MEMBUF_SIZE], udp_port_and_socket_cache[MEMBUF_SIZE],
tcp6_port_and_socket_cache[MEMBUF_SIZE], udp6_port_and_socket_cache[MEMBUF_SIZE];
bool awaiting_reply_from_fe = false; //true when expecting a reply from frontend
bool bTestingMode = false;
int ctmark_to_set;
extern struct nfct_handle *setmark_handle;
bool conntrack_send_anyway = false; //used to tell ct thread to send stats even if there
//was no recent update. Useful when frontend started mid-way and needs ct stats

//fwd delarations
int send_rules();


void set_awaiting_reply_from_fe(bool toggle){
  if (bTestingMode && toggle == false){
    ofstream ff("/tmp/lpfwtest/awaiting_reply.false");
    ff.close();
  }
  awaiting_reply_from_fe = toggle;
}


//split on a delimiter and return chunks
vector<string> split_string(string input, string delimiter=" "){
  vector<string> output;
  int pos = 0;
  string token;
  while (true){
    pos = input.find(delimiter);
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
  cout << "dumping core \n";
  abort();
  //print_trace();
}

//return 2 conntrack marks: input and output
vector<u_int32_t> get_ctmarks(){
  //conntrack mark number for the packet (to be summed with CT_MARK_BASE)
  static u_int32_t ctmark_count = 0;
  static pthread_mutex_t ctmark_mutex = PTHREAD_MUTEX_INITIALIZER;
  _pthread_mutex_lock ( &ctmark_mutex );
  ++ctmark_count;
  vector<u_int32_t>ctmarks;
  ctmarks.push_back(CTMARKIN_BASE + ctmark_count);
  ctmarks.push_back(CTMARKOUT_BASE + ctmark_count);
  _pthread_mutex_unlock ( &ctmark_mutex );
  return ctmarks;
}


void fe_active_flag_set ( const unsigned char boolean )
{
  _pthread_mutex_lock ( &fe_active_flag_mutex );
  bFrontendActive = boolean;
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

//called when a port could not be found in previous cache
//so we build a new cache while at the same time looking for the port

//Note that Linux allows multiple sockets to share the same local port using SO_REUSEPORT
//This is primarily intended for servers
//So in the case where 2 processes are bound to the same local port and simultaneously
//are trying to establish a new connection to the same host:port,
//there will be no way for this function to distinguish which of them sent the packet.
//For now this function picks the first matching socket
int build_port_and_socket_cache(unsigned long &socket_out, const string localaddr, const int localport,
                                const string remoteaddr, const int remoteport, const string proto,
                                const int direction) {
    char rawbuf[4096];
    char laddr[INET6_ADDRSTRLEN] = {0}; //IP4 will comfortably fit there
    char raddr[INET6_ADDRSTRLEN] = {0};
    char lport[5] = {0};
    char rport[5] = {0};
    char state[3] = {0};
    string ip6loopback = "00000000000000000000000000000001";
    int bytesread, i, procnet_fd, *cache;
    bool bSocketFound = false;
    long socket;
    FILE *procnet_file;
    pthread_mutex_t mutex;
    if (proto == "TCP") {
      procnet_file = tcpinfo;
      procnet_fd = tcpinfo_fd;
      cache = tcp_port_and_socket_cache;
      mutex = tcp_port_and_socket_cache_mutex;
    }
    else if (proto == "TCP6") {
      procnet_file = tcp6info;
      procnet_fd = tcp6info_fd;
      cache = tcp6_port_and_socket_cache;
    }
    else if (proto == "UDP") {
      procnet_file = udpinfo;
      procnet_fd = udpinfo_fd;
      cache = udp_port_and_socket_cache;
      mutex = udp_port_and_socket_cache_mutex;
    }
    else if (proto == "UDP6") {
      procnet_file = udp6info;
      procnet_fd = udp6info_fd;
      cache = udp6_port_and_socket_cache;
    }
    i = 0;
    _fseek(procnet_file,0,SEEK_SET);

    //convert *_in args into procnet* format e.g. 127.0.0.1:21787 looks  0100007F:551B
    vector<string>saddr_parts = split_string(localaddr, ".");
    std::stringstream saddr_ss;
    for (int p = saddr_parts.size()-1 ; p >= 0; --p){
      saddr_ss << std::uppercase << std::hex << std::setfill('0') <<
                  std::setw(2) << stoi(saddr_parts[p]);
    }
    string saddr_in_procnet(saddr_ss.str());
    vector<string>daddr_parts = split_string(remoteaddr, ".");
    std::stringstream daddr_ss;
    for (int q = daddr_parts.size()-1 ; q >= 0; --q){
      daddr_ss << std::uppercase << std::hex << std::setfill('0') <<
                  std::setw(2) << stoi(daddr_parts[q]);
    }
    string daddr_in_procnet(daddr_ss.str());
    std::stringstream sport_ss;
    sport_ss << std::uppercase << std::hex << std::setfill('0') <<
                std::setw(4) << localport;
    string sport_in_procnet(sport_ss.str());
    std::stringstream dport_ss;
    dport_ss << std::uppercase << std::hex << std::setfill('0') <<
                std::setw(4) << remoteport;
    string dport_in_procnet(dport_ss.str());


    string debugdata;
    string debugfilename;
    //no matter how much we put here, a read() from proc always gets 4050 bytes
    //per one read operation. Moreover /proc/net/* is smart enough to feed the line
    //up to /r/n and not give you part of the line, so each read will end with /r/n

    _pthread_mutex_lock(&mutex);
    bool bFirstLine = true;
    while ((bytesread = read(procnet_fd, rawbuf, 4096)) > 0) {
      rawbuf[bytesread] = 0; //terminating 0 just in case
      debugdata += string(rawbuf);
      if (proto == "TCP") {debugfilename = "/tmp/procnettcp";}
      else if (proto == "TCP6") {debugfilename = "/tmp/procnettcp6";}
      else if (proto == "UDP") {debugfilename = "/tmp/procnetudp";}
      else if (proto == "UDP6") {debugfilename = "/tmp/procnetudp6";}

      string input(rawbuf);
      vector<string> lines = split_string(input, "\n");
      int j;
      //ignore the last line which is "" due to \n at the end of input
      for (j=0; j < lines.size()-1; ++j){
        if (bFirstLine) { bFirstLine = false; continue;}
        sscanf(lines[j].c_str(),
               "%*s %[0123456789ABCDEF]:%4c %[0123456789ABCDEF]:%4c %2c %*s %*s %*s %*s %*s %ld \n",
               laddr, lport, raddr, rport, state, &socket);
        if (proto == "TCP" || proto == "TCP6"){
          if( (direction == DIRECTION_OUT && !(state[0] == '0' && state[1] == '2')) ||
              (direction == DIRECTION_IN && !(state[0] == '0' && state[1] == 'A')) ){
          //state 02: SYN_SENT for TCP
          //state 0A: listening
          continue;}
        }
        if (proto == "UDP" || proto == "UDP6"){
          if( (direction == DIRECTION_OUT && !(state[0] == '0' && (state[1] == '7' || state[1] == '1'))) ||
              (direction == DIRECTION_IN && !(state[0] == '0' && state[1] == '7')) ){
          //Note: I couldnt find any docu on UDP state 01, but observing /proc/net/udp
          //this seems like a legit state of the sending socket
          //state 07: listening for UDP
          continue;}
        }

        if (socket == 0){
          cout << "socket == 0 \n";
          goto dump_debug;}

        if(  ((proto == "TCP" || proto == "UDP") && (raddr[6] == '7' && raddr[7] == 'F')) ||
             ((proto == "TCP6" || proto == "UDP6") && (string(raddr) == ip6loopback))){
            //0x7F == 127, for IP6 ::1 is loopback
            //we're not interested in destinations within localhost IP range
            continue;}

        std::stringstream ss;
        ss << lport;
        ss << std::hex;
        int sport_int;
        ss >> sport_int;

        cache[i*2] = (unsigned long) sport_int;
        cache[i*2+1] = socket;
        if (lport == sport_in_procnet){
          //TODO: assert here that raddr:rport = 0 because this is a listening socket
          //it must not know it's peer at this point
          if (bSocketFound){
            cout << "Duplicate connection detected \n";
            //goto dump_debug;
          }
          socket_out = socket;
          cout << "socket found with state:" << string(state) << "\n";
          bSocketFound = true;
        }
      }
      i += j;
    }
    if (bytesread == -1) { die(strerror(errno)); }
    cache[i*2] = (unsigned long)MAGIC_NO;
    _pthread_mutex_unlock(&mutex);
    if (!bSocketFound) {
      //writing debug data only when socket not found
      ofstream debugfile(debugfilename, ios::out | ios::binary);
      debugfile << debugdata;
      debugfile << "\n";
      debugfile << "processed " << i << "lines\n";
      debugfile.close();
      return 0;
    }
    else { return 1; }

dump_debug:
    ;
    ofstream debugfile(debugfilename, ios::out | ios::binary);
    debugfile << debugdata;
    debugfile << "\n";
    debugfile << "processed " << i << "lines\n";
    debugfile.close();
    abort();
}


int fe_active_flag_get()
{
  _pthread_mutex_lock ( &fe_active_flag_mutex );
  bool temp = bFrontendActive;
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
  string path = "/proc/" + to_string(mypid) + "/stat";
  stream = fopen (path.c_str(), "r" );
  if (stream == NULL) {
    cout << "***********************************PROCPIDSTAT no found for " << mypid << "\n";
    return -1; }
  fscanf ( stream, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s"
           "%*s %*s %*s %*s %*s %*s %*s %llu", &starttime );
  _fclose ( stream );
  return starttime;
}


int ruleslist_add( const string path, const string pid, const string perms,
                   const bool active, const string sha, const unsigned long long stime,
                   const int ctmark, const bool first_instance){
  int retctmark;
  int i;
  _pthread_mutex_lock ( &rules_mutex );
  if (path == KERNEL_PROCESS) {
    //make sure it is not a duplicate KERNEL_PROCESS
    for(i=0; i < rules.size(); i++){
      if (rules[i].path != KERNEL_PROCESS) continue;
      if (rules[i].pid == pid) { //same IP, quit
         die();
        _pthread_mutex_unlock ( &rules_mutex );
        return 0;
      }
    }
  }
  else {
    //make sure it's not a duplicate of a regular (i.e. non-kernel) rule
    for(i=0; i < rules.size(); i++){
      if (rules[i].path == path && rules[i].pid == pid){
        cout << "path " << path << " pid " << pid << "\n";
        die("duplicate rule");
        //_pthread_mutex_unlock ( &rules_mutex );
        //return 0;
      }
    }
  }
  rule newrule;
  newrule.path = path;
  newrule.pid = pid;
  newrule.perms = perms;
  newrule.is_active = active;
  newrule.stime = stime;
  //rules added by frontend dont have their sha
  if (sha == "") { newrule.sha = get_sha256_hexdigest(path); }
  else { newrule.sha = sha; }
  if (ctmark == 0) {
    vector<u_int32_t>ctmarks = get_ctmarks();
    newrule.ctmark_in = ctmarks[0];
    retctmark = newrule.ctmark_out = ctmarks[1];
  }
  else { // ctmark > 0 => assign parent's ctmark
    //either ctmark is for in or out traffic
    if (ctmark >= CTMARKIN_BASE){
      newrule.ctmark_in = ctmark;
      retctmark = newrule.ctmark_out = ctmark - CTMARK_DELTA;
    }
    else {
      retctmark = newrule.ctmark_out = ctmark;
      newrule.ctmark_in = ctmark + CTMARK_DELTA;
    }
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
  rules.push_back(newrule);
  _pthread_mutex_unlock ( &rules_mutex );
  if (perms == ALLOW_ALWAYS || perms == DENY_ALWAYS) {
    rules_write();
  }
  return retctmark;
}


void ruleslist_delete_all ( const string path) {
  bool bRulesChanged = false;
  bool bNeedToWriteRulesfile = false;
  _pthread_mutex_lock ( &rules_mutex );
  for(int i=0; i < rules.size(); i++){
    if (rules[i].path != path) continue;
    if (rules[i].is_active) {
      _closedir (rules[i].dirstream);
      ctmark_to_delete_in = rules[i].ctmark_in;
      ctmark_to_delete_out = rules[i].ctmark_out;
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
  _pthread_mutex_unlock ( &rules_mutex );
  if (! bRulesChanged) die(); //couldnt find the rule
  if (bNeedToWriteRulesfile){
    rules_write();}
  if (bFrontendActive) {
    send_rules();}
}


//Find and delete one entry in rules
//the calling thread holds the rules mutex
void ruleslist_delete_one ( const string path, const string pid ) {
  for(int i=0; i < rules.size(); i++){
    if (rules[i].path != path || rules[i].pid != pid) continue;
    //else found
    _closedir (rules[i].dirstream);
    ctmark_to_delete_in = rules[i].ctmark_in;
    ctmark_to_delete_out = rules[i].ctmark_out;
    bool was_active = rules[i].is_active;
    rules.erase(rules.begin()+i);
    //remove tracking for this process's active connection only if this process was active
    if (was_active) {
      _pthread_mutex_lock(&condvar_mutex);
      predicate = TRUE;
      _pthread_mutex_unlock(&condvar_mutex);
      _pthread_cond_signal(&condvar);
    }
    return; // and return
  }
  die(); //Fatal: couldnt find the rule to delete
}


//Search cache which thread_build_pid_and_socket_cache built
int search_pid_and_socket_cache(const long socket_in, string &path_out,
                                    string &pid_out, int &ctmark_out){
  _pthread_mutex_lock ( &rules_mutex );
  vector<rule> rulescopy = rules;
  _pthread_mutex_unlock ( &rules_mutex );
  int i,j,retval;
  for(i = 0; i < rulescopy.size(); i++){
    if (! rulescopy[i].is_active) continue;
    for(j=0; j < rulescopy[i].sockets.size(); ++j){
      if (rulescopy[i].sockets[j] != socket_in) {continue;}
      if (rulescopy[i].perms == ALLOW_ONCE || rulescopy[i].perms == ALLOW_ALWAYS) {
        retval = CACHE_TRIGGERED_ALLOW;}
      else {retval = CACHE_TRIGGERED_DENY;}
      path_out = rulescopy[i].path;
      pid_out = rulescopy[i].pid;
      int stime = starttimeGet(atoi (rulescopy[i].pid.c_str()));
      if (stime == -1){
        return SOCKET_IN_CACHE_NOT_FOUND;}
      if (rulescopy[i].stime != stime) {
        return SPOOFED_PID;}
      ctmark_out = rulescopy[i].ctmark_out;
      return retval;
    }
  }
  return SOCKET_IN_CACHE_NOT_FOUND;
}


//Build the cache of proc/PID/fd sockets for all running processes which
//lpfw keeps track of. The likelihood is very high that a new connection
//request will be made by a process which lpfw already keeps track of.
//Thus we can save some CPU, whereas otherwise we'd have to scan each
// <PID>/fd in the whole /proc/ tree
void* thread_build_pid_and_socket_cache ( void *ptr ){
  char proc_pid_exe[32];
  string proc_pid_fd_path;
  struct timespec refresh_timer;
  refresh_timer.tv_sec=0;
  refresh_timer.tv_nsec=1000000000/4;
  struct dirent *m_dirent;
  struct timeval time;
  int delta;

  while (true) {
    while(nanosleep(&refresh_timer, &refresh_timer));
    gettimeofday(&time, NULL);
    _pthread_mutex_lock(&lastpacket_mutex);
    delta = time.tv_sec - lastpacket.tv_sec;
    _pthread_mutex_unlock(&lastpacket_mutex);
    //preserve CPU cycles and don't build the cache if it's
    //been more than 1 second since the last new connection was detected
    if (delta > 1) continue;

    _pthread_mutex_lock ( &rules_mutex );
    for(int i = 0; i < rules.size(); i++){
      if (! rules[i].is_active || rules[i].path == KERNEL_PROCESS) continue;
      rules[i].sockets.clear();
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
        rules[i].sockets.push_back(atol(&proc_pid_exe[8]));
        j++;
      } //while (m_dirent = readdir ( rule->dirstream ))
      if (errno==0) continue; //readdir reached EOF, thus errno hasn't changed from 0
      else die();
    }
    _pthread_mutex_unlock ( &rules_mutex );
  } // while(true)
}


//packets from here will end up in nfq_handle
void* thread_nfq_in ( void *nfqfd )
{
  int nfqfd_in = *((int *)(nfqfd));
//endless loop of receiving packets and calling a handler on each packet
  int rv;
  char buf[4096] __attribute__ ( ( aligned ) );
  while ( ( rv = recv ( nfqfd_in, buf, sizeof ( buf ), 0 ) ) && rv >= 0 ){
    nfq_handle_packet ( globalh_in, buf, rv );
  }
}

void* thread_nfq_out ( void *nfqfd )
{
  int nfqfd_out = *((int *)(nfqfd));
//endless loop of receiving packets and calling a handler on each packet
  int rv;
  char buf[4096] __attribute__ ( ( aligned ) );
  while ( ( rv = recv ( nfqfd_out, buf, sizeof ( buf ), 0 ) ) && rv >= 0 ){
    nfq_handle_packet ( globalh_out, buf, rv );
  }
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
        cout << "ERROR writing to socket. UNREGISTERing \n";
        set_awaiting_reply_from_fe(false);
        _close(newsockfd);
        return;
      }
    }
    bzero(buffer,256);
    n = read(newsockfd,buffer,255);
    if (n < 0) continue; //no data
    if (n == 0){
      //usually because the frontend abruptly closed the socket
      set_awaiting_reply_from_fe(false);
      _close(newsockfd);
      return;
    }

    vector<string> string_parts = split_string(string(buffer));
    string comm = string_parts[0];
    if (comm == "LIST"){
      cout << "in LIST \n";
      //We could send right from here, however calling a special function is cleaner
      send_rules();
      //Tell conntrack to send stats even if there was no recent update
      //conntrack will toggle it back to false
      conntrack_send_anyway = true;
    }
    else if (comm == "DELETE"){ // comm path
      string path = base64_decode(string_parts[1]);
      cout << "backend deleting " << path << "\n";
      ruleslist_delete_all(path);
    }
    else if (comm == "WRITE"){ //Not in use
      rules_write();
    }
    else if (comm == "ADD"){ //ADD path pid perms
      cout << "ADDing a rule \n";
      if (!awaiting_reply_from_fe) die();
      string path = base64_decode(string_parts[1]);
      string pid = string_parts[2];
      string perms = string_parts[3];
      if (sent_path != string_parts[1] || sent_pid != pid){
        die("Expected " + sent_path + " but got " + path);}
      if (perms == "IGNORED") set_awaiting_reply_from_fe(false);
      else if (path == "KERNEL_PROCESS"){
        ruleslist_add(KERNEL_PROCESS, pid, perms, TRUE, "", 0, 0 ,TRUE);
      }
      else {
        string procpath = "/proc/" + pid + "/exe";
        char exepathbuf[PATHSIZE];
        string sha;
        memset ( exepathbuf, 0, PATHSIZE );
        readlink (procpath.c_str(), exepathbuf, PATHSIZE-1 );
        if (exepathbuf != path){
          cout << "Frontend asked to add a process that is no longer running \n";
          set_awaiting_reply_from_fe(false);
          continue;
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
       ruleslist_add(path, pid, perms, true, "", atoi(sent_stime.c_str()), 0 ,TRUE);
       set_awaiting_reply_from_fe(false);
       requestQueue = queue<string>(); //clear the queue
       send_rules();
      }
    }
    else if (comm == "UNREGISTER"){
      _close(newsockfd);
      set_awaiting_reply_from_fe(false);
      return;
    }
    else {cout << "unknown command: " << comm << "size:" << n << "\n";}
  } //while (true)
}


//wait for the frontend to connect
void* thread_tcp_server ( void *data ) {
   prctl(PR_SET_NAME,"daemon_server",0,0,0);

   int sockfd, newsockfd;
   struct sockaddr_in serv_addr, cli_addr;
   socklen_t clilen;

   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) error("ERROR opening socket");
   bzero((char *) &serv_addr, sizeof(serv_addr));

   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(0);
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) perror("ERROR on binding");
   //get local port
   int local_port;
   struct sockaddr_in sin;
   socklen_t addrlen = sizeof(sin);
   if(getsockname(sockfd, (struct sockaddr *)&sin, &addrlen) == 0 &&
     sin.sin_family == AF_INET && addrlen == sizeof(sin)) {
     local_port = ntohs(sin.sin_port);
   }

   cout << "Daemon tcp port:" << local_port << "\n";
   ofstream myfile("/tmp/lpfwcommport");
   myfile << to_string(local_port);
   myfile.close();

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
     bFrontendActive = true;
     tcp_server_process_messages(newsockfd);
     bFrontendActive = false;
     //tcp_server_process_messages returns when frontend unregisters
     //we can listen for a new frontend connection
   }
}


//scan procfs and remove/mark inactive those processes that are no longer running
void* thread_refresh ( void* ptr ){
  prctl(PR_SET_NAME,"refresh",0,0,0);
  ptr = 0;     //to prevent gcc warnings of unused variable
  char exe_path[PATHSIZE] = {'\0'};
  bool prevIterationHadAnUpdate = false;
  bool thisIterationHadAnUpdate = false;

  while (true){
    thisIterationHadAnUpdate = false;
    _pthread_mutex_lock ( &rules_mutex );
    for(int i=0; i < rules.size(); i++){
       //only interested in processes which produced some traffic already
       if (!rules[i].is_active || rules[i].path == KERNEL_PROCESS) continue;
       string proc_pid_exe = "/proc/" + rules[i].pid + "/exe";
       memset ( exe_path, 0, PATHSIZE );
       //readlink doesn't fail if PID is running
       if ( readlink ( proc_pid_exe.c_str(), exe_path, PATHSIZE ) != -1 ) continue;
       //else the PID is not running anymore
       if (rules[i].perms == ALLOW_ONCE || rules[i].perms == DENY_ONCE){
         ruleslist_delete_one ( rules[i].path, rules[i].pid );
         //To keep this function's logic simple we dont iterate anymore
         //(although we could) but break the for loop
         thisIterationHadAnUpdate = true;
         break;
       }
       //Only delete *ALWAYS rule if there is at least one more rule in rules with the same PATH
       //and with the same *ALWAYS permissions
       //If the rule is the only one in rules with such PATH, simply toggle off is_active flag
       //(because we want an *ALWAYS rule always to be present in the rules)
       if (rules[i].perms == ALLOW_ALWAYS || rules[i].perms == DENY_ALWAYS){
         bool bFoundAnotherOne = false;
         for(int j=0; j < rules.size(); j++){ //scan all rules again
           if (j == i) continue; //Make sure we don't find our own rule
           if (rules[j].path != rules[i].path) continue;
           if (rules[j].perms != rules[i].perms) continue;
           bFoundAnotherOne = true;
           ruleslist_delete_one ( rules[i].path, rules[i].pid );
           rules_write(true);
           thisIterationHadAnUpdate = true;
           break;
         }
         if (bFoundAnotherOne){break;} //out of rules iteration
         //else this is the only *ALWAYS rule with such PATH
         rules[i].pid = "0";
         rules[i].is_active = false;
         //conntrack marks will be used by the next instance of app
         vector<u_int32_t>ctmarks = get_ctmarks();
         rules[i].ctmark_in = ctmarks[0];
         rules[i].ctmark_out = ctmarks[1];
         thisIterationHadAnUpdate = true;
         break; //out of rules iteration
       }
    } //for(int i=0; i < rules.size(); i++)
    _pthread_mutex_unlock ( &rules_mutex );

    if (thisIterationHadAnUpdate){
      prevIterationHadAnUpdate = true;
      continue; //to while (true)
    }
    else if (prevIterationHadAnUpdate){
      if (bFrontendActive) {
        send_rules();}
      prevIterationHadAnUpdate = false;
    }
    else {
      //no updates in previous or this iteration
      sleep ( REFRESH_INTERVAL );
    }
  } //while (true)
}


//Load rules from rulesfile at startup
void rules_load(){
  ifstream inputFile(rules_file->filename[0]);
  string line;
  int pos;
  bool is_full_path_found = false;
  bool is_permission_found = false;
  bool is_sha256_hexdigest_found = false;
  bool is_conntrack_mark_found = false;
  string full_path = "";
  string permission = "";
  string sha256_hexdigest = "";
  int conntrack_mark = 0;

  while (getline(inputFile, line))
  {
    if (line[0] == '#') continue;
    if (line == ""){
      if (is_full_path_found && is_permission_found && is_sha256_hexdigest_found){
        //the end of the rule parameters
        rule newrule;
        newrule.path = full_path;
        newrule.perms = permission;
        newrule.sha = sha256_hexdigest;
        newrule.pid = "0";
        newrule.is_active = false;
        newrule.stime = 0;
        newrule.first_instance = true;
        newrule.ctmark_out = 0;
        newrule.ctmark_in = 0;
        if (is_conntrack_mark_found){
          newrule.ctmark_out = conntrack_mark;
          newrule.ctmark_in = conntrack_mark+CTMARK_DELTA;
          newrule.is_fixed_ctmark = true;
        }
        rules.push_back(newrule);
        is_full_path_found = false;
        is_permission_found = false;
        is_sha256_hexdigest_found = false;
        is_conntrack_mark_found = false;
        full_path = "";
        permission = "";
        sha256_hexdigest = "";
        conntrack_mark = 0;
      }
      continue;
    }
    if ((pos = line.find(" ")) == string::npos) return; //TODO should throw?
    //mandatory parameters
    if (!is_full_path_found){
      if (line.substr(0,11) != "full_path= ") return; //TODO should throw?
      //trim leading spaces
      line = line.substr(pos, string::npos);
      line = line.substr( line.find_first_not_of(" "), string::npos);
      full_path = line;
      is_full_path_found = true;
      continue;
    }
    if (!is_permission_found){
      if (line.substr(0,12) != "permission= ") return; //TODO should throw?
      //trim leading spaces
      line = line.substr(pos, string::npos);
      line = line.substr( line.find_first_not_of(" "), string::npos);
      permission = line;
      is_permission_found = true;
      continue;
    }
    if (!is_sha256_hexdigest_found){
      if (line.substr(0,18) != "sha256_hexdigest= ") return; //TODO should throw?
      //trim leading spaces
      line = line.substr(pos, string::npos);
      line = line.substr( line.find_first_not_of(" "), string::npos);
      sha256_hexdigest = line;
      is_sha256_hexdigest_found = true;
      continue;
    }
    if (!is_conntrack_mark_found){
      if (line.substr(0,16) != "conntrack_mark= ") return; //TODO should throw?
      //trim leading spaces
      line = line.substr(pos, string::npos);
      line = line.substr( line.find_first_not_of(" "), string::npos);
      conntrack_mark = std::stoi(line);
      is_conntrack_mark_found = true;
      continue;
    }
  }
  inputFile.close();
}


//iterate over rulescopy removing all rules which are not *ALWAYS
//or which are duplicates of other *ALWAYS rules with the same path
//this will leave us with rulescopy with unique *ALWAYS rules
void rules_write(bool mutex_being_held){
  if (!mutex_being_held) _pthread_mutex_lock ( &rules_mutex );
  vector<rule> rulescopy = rules;
  if (!mutex_being_held) _pthread_mutex_unlock ( &rules_mutex );
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
  string string_to_write =
      "\n"
      "# Leopard Flower personal firewall rules list\n"
      "# lines startng with # are comments and will be ignored\n"
      "# blank line is used to separate individual rules\n"
      "# (Each parameter must have one or more spaces after the = sign and terminate with a newline)\n"
      "\n"
      "# Mandatory parameters (strictly in this order):\n"
      "# full_path= followed by the full path to the executable\n"
      "# permission= followed by either ALLOW_ALWAYS or DENY_ALWAYS\n"
      "# sha256_hexdigest= followed by sha256 UPPERCASE hexdigest with any leading zeroes\n"
      "# Optional parameters:\n"
      "# conntrack_mark= followed by an integer\n"
      "# (conntrack_mark can be manually assigned by the user in this file. This will enable the user\n"
      "# to create more complex netfilter rules for the application, e.g. rate-limiting, IP/port blocking etc\n"
      "# conntrack_mark set here will be used for outgoing connections\n"
      "# for incoming connections conntrack_mark+10000 will be used)\n"
      "\n"
      "# Make sure there is a blank line at the end of this file\n"
      "\n"
      "# Example rules list:\n"
      "# full_path=        /home/myusername/app1\n"
      "# permission=       ALLOW_ALWAYS\n"
      "# sha256_hexdigest= 3719407990275C319C882786125B1F148CC163FA3BF4C7712092034BBA06CE4D\n"
      "# conntrack_mark=   11443\n"
      "\n"
      "# full_path=        /home/myusername/app2\n"
      "# permission=       ALLOW_ALWAYS\n"
      "# sha256_hexdigest= 9AF0F74366D0B3D1415AB6DF5D7E2429BF5CB5AC901B5ECFCC3DD51DA4B83D75\n"
      "\n";

  for(i = 0; i < rulescopy.size(); i++){
    string_to_write += "full_path=        " + rulescopy[i].path + "\n";
    string_to_write += "permission=       " + rulescopy[i].perms + "\n";
    string_to_write += "sha256_hexdigest= " + rulescopy[i].sha + "\n";
    if (rulescopy[i].is_fixed_ctmark){
      string_to_write += "conntrack_mark=   " + to_string(rulescopy[i].ctmark_out) + "\n";
    }
    string_to_write += "\n";
  }
  ofstream myfile(rules_file->filename[0]);
  myfile << string_to_write;
  myfile.close();
}


//This function may be called on 3 occasions:
//1. A rule which was loaded on startup has seen its first packet
//2. socket_active_processes_search() didnt find the process because
///proc/<PID>/fd socket entry wasn't yet created
//3. (most usual case) A process associated with socket was found and now we need to check
//if another rule with the same path is in rules. If so, we are either a fork()ed child or a new instance
int path_find_in_rules ( int &ctmark_out, const string path_in,
                             const string pid_in, unsigned long long stime_in, bool going_out){
  _pthread_mutex_lock ( &rules_mutex );
  vector<rule> rulescopy = rules;
  _pthread_mutex_unlock ( &rules_mutex );

  vector<rule> rulesWithTheSamePath;
  int i,retval;
  for(i = 0; i < rulescopy.size(); ++i) {
    if (rulescopy[i].path == path_in) {
      if (rulescopy[i].pid == pid_in){
        //socket_active_processes_search() didnt pick it up, try again
        return SEARCH_ACTIVE_PROCESSES_AGAIN;
      }
      rulesWithTheSamePath.push_back(rulescopy[i]);
    }
  }
  if (!rulesWithTheSamePath.size()) {return PATH_IN_RULES_NOT_FOUND;}
  if (!rulesWithTheSamePath[0].is_active){
    //A rule which was loaded on startup has seen its first packet
    rule loaded_rule = rulesWithTheSamePath[0];
    string sha = get_sha256_hexdigest(loaded_rule.path.c_str());
    if (loaded_rule.sha != sha) {return SHA_DONT_MATCH; }
    _pthread_mutex_lock ( &rules_mutex );
    bool bRuleFound = false;
    //find the rule again (in case rules have changed while the lock was not held)
    for(i = 0; i < rules.size(); ++i) {
      if (rules[i].path != loaded_rule.path) continue;
      //else
      rules[i].pid = pid_in;
      rules[i].is_active = true;
      rules[i].stime = stime_in;
      rules[i].pidfdpath = "/proc/" + pid_in + "/fd/";
      DIR *dirstream = opendir(rules[i].pidfdpath.c_str());
      //if the app immediately terminated we may get NULL
      if (dirstream != NULL) rules[i].dirstream = dirstream;
      if (! rules[i].is_fixed_ctmark){
        vector<u_int32_t>ctmarks = get_ctmarks();
        rules[i].ctmark_in = ctmarks[0];
        rules[i].ctmark_out = ctmarks[1];
      }
      if (going_out) ctmark_out = rules[i].ctmark_out;
      else ctmark_out = rules[i].ctmark_in;
      _pthread_mutex_unlock ( &rules_mutex );
      bRuleFound = true;
      break;
    }
    assert (bRuleFound);

    if (loaded_rule.perms == ALLOW_ALWAYS) { retval = PATH_FOUND_IN_DLIST_ALLOW; }
    else if (loaded_rule.perms == DENY_ALWAYS) { retval = PATH_FOUND_IN_DLIST_DENY; }
    else die("inactive_rule.perms != *_ALWAYS"); //should never get here
    if (bFrontendActive) {
     send_rules();
    }
    return retval;
  }

  else if (rulesWithTheSamePath[0].is_active){
    for(i = 0; i < rulesWithTheSamePath.size(); ++i) {
      assert(rulesWithTheSamePath[i].is_active);
    }
    //determine if this is a new instance or a fork()d child. Here is how:
    //
    // 1. Get new process's(NP) PPID.(parent PID)
    // 2. Is there a rule with the same PATH as NP AND PID == PPID?
    // 3. If no then we have a new instance, go to step A1
    // 4. If yes, we have a fork()ed process, go to step B1
    //
    // A1. Are there rules with the same PATH as NP AND *ALWAYS perms? If yes,
    //then create a new rule, copy parent's attributer over to NP and continue;
    // A2. If No, i.e. there either aren't any rules with the same PATH as NP OR
    //there are rules with the same path as NP AND *ONCE perms, then query user.
    //
    // B1. Create a new rule, copy parent's attributes over to NP and continue.
    // --------------------------

    string proc_stat_path = "/proc/" + pid_in + "/stat";
    FILE *stream1;
    if ( (stream1 = fopen ( proc_stat_path.c_str(), "r" ) ) == NULL ) return PROCFS_ERROR;
    char ppid[16];
    fscanf ( stream1, "%*s %*s %*s %s", ppid );
    _fclose ( stream1);

    //is it a fork()ed child? Find the real parent.
    for(i = 0; i < rulesWithTheSamePath.size(); i++) {
      if (rulesWithTheSamePath[i].pid != ppid) continue;
      //we get here if we have a fork()ed child
      cout << "***********FOUND A FORKED CHILD \n";
      rule parent_rule = rulesWithTheSamePath[i];
      if (parent_rule.perms == ALLOW_ALWAYS || parent_rule.perms == ALLOW_ONCE){
        retval = FORKED_CHILD_ALLOW;}
      else if (parent_rule.perms == DENY_ALWAYS || parent_rule.perms == DENY_ONCE){
        retval = FORKED_CHILD_DENY;}
      unsigned long long stime = starttimeGet ( atoi ( pid_in.c_str() ) );
      ctmark_out = ruleslist_add ( path_in, pid_in, parent_rule.perms, TRUE,
                                   parent_rule.sha, stime, 0, FALSE );
      if (bFrontendActive) {
        send_rules();
      }
      return retval;
    }
    //we get here when we have a new instance,
    //check that instance launched from unmodified binary
    string sha = get_sha256_hexdigest(path_in.c_str());
    if (sha != rulesWithTheSamePath[0].sha ) {return SHA_DONT_MATCH; }
    // A1. Are there any rules with the same PATH as NP AND *ALWAYS perms? If yes,
    // then create new rule, copy parent's attributes over to NP and continue;
    // A2. If No, i.e. there either aren't any rules with the same PATH as NP OR
    //there are entries with the same path as NP AND *ONCE perms, then query user.
    for(i = 0; i < rulesWithTheSamePath.size(); ++i) {
      if (!(rulesWithTheSamePath[i].perms == ALLOW_ALWAYS ||
            rulesWithTheSamePath[i].perms == DENY_ALWAYS)) continue;
      //else
      ctmark_out = ruleslist_add ( path_in, pid_in, rulesWithTheSamePath[i].perms,
                                   TRUE, rulesWithTheSamePath[i].sha, stime_in, 0 ,FALSE);
      if (bFrontendActive) {
        send_rules();
      }
      if (rulesWithTheSamePath[i].perms == ALLOW_ALWAYS) return NEW_INSTANCE_ALLOW;
      else if (rulesWithTheSamePath[i].perms == DENY_ALWAYS) return NEW_INSTANCE_DENY;
    }
    return PATH_IN_RULES_FOUND_BUT_PERMS_ARE_ONCE;
  } //else if (rulescopy[i].is_active){
}


//Try to find the socket among the active processes in lpfw rules
//This is the 2nd searching place and not the 1st, because searching in cache is much cheaper
int socket_active_processes_search ( const long mysocket_in, string &m_path_out,
                                     string &m_pid_out, int  &ctmark_out){
  string path_dir;
  string path_file;
  DIR *m_dir;
  struct dirent *m_dirent;

  _pthread_mutex_lock ( &rules_mutex );
  vector<rule> rulescopy = rules;
  _pthread_mutex_unlock ( &rules_mutex );

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
      char socketbuf[32] = {'\0'};
      int size = readlink (path_file.c_str(), socketbuf, SOCKETBUFSIZE ); //no trailing 0
      if (size == -1) continue;
      socketbuf[size] = 0; //set trailing 0
      if (find_socket != socketbuf) continue;
      //else match found
      string procexepath = "/proc/" + rulescopy[i].pid + "/exe";
      char exepathbuf[PATHSIZE] = {'\0'};
      size = readlink (procexepath.c_str(), exepathbuf, PATHSIZE ); //no trailing 0
      if (size == -1){
        fprintf(stderr, "Error in readlink %d - %s\n", errno, strerror(errno));
        _closedir ( m_dir );
        return SOCKET_ACTIVE_PROCESSES_NOT_FOUND;
      }
      exepathbuf[size] = 0;
      m_path_out = exepathbuf;
      m_pid_out = rulescopy[i].pid;
      _closedir ( m_dir );
      unsigned long long stime = starttimeGet ( atoi ( rulescopy[i].pid.c_str() ) );
      if ( rulescopy[i].stime != stime ) {
        printf ("SPOOFED_PID in %s %s %d", rulescopy[i].path.c_str(),  __FILE__, __LINE__ );
        return SPOOFED_PID;
      }
      if (rulescopy[i].perms == ALLOW_ONCE  || rulescopy[i].perms == ALLOW_ALWAYS) {
        ctmark_out = rulescopy[i].ctmark_out;
        return SOCKET_FOUND_IN_DLIST_ALLOW;
      }
      if (rulescopy[i].perms == DENY_ONCE || rulescopy[i].perms == DENY_ALWAYS) {
        return SOCKET_FOUND_IN_DLIST_DENY;
      }
    } //while ( m_dirent = readdir ( m_dir ) )
    _closedir ( m_dir );
  } //for(i = 0; i < rulescopy.size(); i++)
  return SOCKET_ACTIVE_PROCESSES_NOT_FOUND;
}


//Try to find the socket by scanning the whole /proc/<PID>/fd tree
int socket_procpidfd_search ( const long mysocket_in, string &m_path_out,
                              string &m_pid_out, u_int64_t &stime_out) {
  struct dirent *proc_dirent, *fd_dirent;
  DIR *proc_DIR, *fd_DIR;
  string fdpath;   // holds path to /proc/<pid>/fd/<number_of_inode_opened>
  // buffers to hold readlink()ed values of /proc/<pid>/exe and /proc/<pid>/fd/<inode>
  char exepathbuf[PATHSIZE] = {'\0'};
  char socketbuf[SOCKETBUFSIZE] = {'\0'};
  string find_socket = "socket:[" + to_string(mysocket_in) + "]";

  if ((proc_DIR = opendir("/proc")) == NULL) return SOCKET_NOT_FOUND_IN_PROCPIDFD;
  while (true){
    proc_dirent = readdir ( proc_DIR );
    if (proc_dirent == NULL) {
      _closedir ( proc_DIR );
      break;
    }
    if (! ((47 < proc_dirent->d_name[0]) && (proc_dirent->d_name[0] < 58))) continue; //only ASCII 1 thru 9 allowed
    string path = "/proc/" + string(proc_dirent->d_name) + "/fd";
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
      if (size == -1) continue;
      socketbuf[size] = 0;
      if (find_socket != socketbuf) continue;
      //else we found our socket!!!!
      path = "/proc/" + string(proc_dirent->d_name) + "/exe";
      try {
        stime_out  = starttimeGet ( atoi ( proc_dirent->d_name ) );
        size = _readlink ( path.c_str(), exepathbuf, PATHSIZE - 1 );
      } catch (...){
        _closedir ( fd_DIR );
        _closedir ( proc_DIR );
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


//Not in use now
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


//Not in use now
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


//Not in use
int inkernel_check(const int port, const int proto)
{
//The only way to distinguish kernel sockets is that they have inode=0 and uid=0
//But regular process's sockets sometimes also have inode=0 (I don't know why)
//+ root's sockets have uid == 0
//So we just assume that if inode==0 and uid==0 - it's a kernel socket

  FILE *procnet, *procnet6;
  int procnet_fd, procnet6_fd;
  char procnet_buf[4096], procnet6_buf[4096];
  int bytesread,bytesread6;
  char newline[2] = {'\n','\0'};
  char uid[2] = {'0','\0'};
  long socket_next;
  int port_next;
  char *token, *lasts;

  string procnet_path, procnet6_path;
  if (proto == PROTO_TCP){
    procnet_path = TCPINFO;
    procnet6_path = TCP6INFO;
  }
  else if (proto == PROTO_UDP){
    procnet_path = UDPINFO;
    procnet6_path = UDP6INFO;
  }

  if ( ( procnet = fopen ( procnet_path.c_str(), "r" ) ) == NULL ) {
    M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
    exit (PROCFS_ERROR);
  }
  procnet_fd = fileno(procnet);
  memset(procnet_buf,0, 4096);
  while ((bytesread = read(procnet_fd, procnet_buf, 4060)) > 0) {
    if (bytesread == -1) {
      perror ("read");
      return -1;
    }
    token = strtok_r(procnet_buf, newline, &lasts); //skip the first line (column headers)
    while ((token = strtok_r(NULL, newline, &lasts)) != NULL) {
      //take a line until EOF
      sscanf(token, "%*s %*8s:%4X %*s %*s %*s %*s %*s %s %*s %ld", &port_next, uid, &socket_next);
      if (port_next != port ) continue;
      //else
      if (socket_next != 0){
          _fclose(procnet);
          return SOCKET_CHANGED_FROM_ZERO;
      }
      else if (!strcmp (uid, "0")){
          _fclose(procnet);
          return INKERNEL_SOCKET_FOUND;
      }
      else{
        _fclose(procnet);
        return SOCKET_ZERO_BUT_UID_NOT_ZERO;
      }
    }
  }
  _fclose(procnet);

//not found in /proc/net/{tcp,udp}, search in /proc/net/{tcp6,udp6}

  if ( ( procnet6 = fopen ( procnet6_path.c_str(), "r" ) ) == NULL ) {
    M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
    exit (PROCFS_ERROR);
  }
  procnet6_fd = fileno(procnet6);
  memset(procnet6_buf,0, 4096);
  while ((bytesread6 = read(procnet6_fd, procnet6_buf, 4060)) > 0) {
    if (bytesread6 == -1) {
      perror ("read");
      return -1;
    }
    token = strtok_r(procnet6_buf, newline, &lasts); //skip the first line (column headers)
    while ((token = strtok_r(NULL, newline, &lasts)) != NULL) {
      //take a line until EOF
      sscanf(token, "%*s %*32s:%4X %*s %*s %*s %*s %*s %s %*s %ld", &port_next, uid, &socket_next);
      if (port_next != port ) continue;
      //else
      if (socket_next != 0){
          _fclose(procnet6);
          return SOCKET_CHANGED_FROM_ZERO;
      }
      else if (!strcmp (uid, "0")){
          _fclose(procnet6);
          return INKERNEL_SOCKET_FOUND;
      }
      else{
        _fclose(procnet6);
        return SOCKET_ZERO_BUT_UID_NOT_ZERO;
      }
    }
  }
  _fclose(procnet6);
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
//Not in use - maybe can be used in debugging
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


//find process that owns the socket
int socket_handle ( const long socket_in, int &ctmark_out, string &path_out,
                    string &pid_out, u_int64_t &stime_out, int srctcp){
//the last arg srctcp is used for debug purposes only
  cout << "in socket handle \n";
  int retval;
  retval = search_pid_and_socket_cache(socket_in, path_out, pid_out, ctmark_out);
  if (retval != SOCKET_IN_CACHE_NOT_FOUND){
    cout << "found in pid and socket cache \n";
    M_PRINTF (MLOG_DEBUG2, "(cache)");
    if (bTestingMode) assert (strstr(path_out.c_str(), "/tmp/lpfwtest/testprocess") != NULL);
    return retval;
  }
  retval = socket_active_processes_search ( socket_in, path_out, pid_out, ctmark_out );
  if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND ){
    if (bTestingMode) assert (strstr(path_out.c_str(), "/tmp/lpfwtest/testprocess") != NULL);
    cout << "found among active processes \n";
    return retval;
  }
  retval = socket_procpidfd_search ( socket_in, path_out, pid_out, stime_out );
  if (retval == SOCKET_NOT_FOUND_IN_PROCPIDFD){ return retval; }
  else if (retval == SOCKET_FOUND_IN_PROCPIDFD){
    cout << "found after searching procfd \n";
    if (bTestingMode){
      if (strstr(path_out.c_str(), "/tmp/lpfwtest/testprocess") == NULL) {
        cout << "wrong path " << path_out << "\n";
        cout << "pid " << pid_out << "\n";
        cout << "socket " << socket_in << "\n";
        cout << "src port " << to_string(srctcp) << "\n";
        die();
      }
    }
    retval = path_find_in_rules ( ctmark_out, path_out, pid_out, stime_out, true);
    if (retval == SEARCH_ACTIVE_PROCESSES_AGAIN){
      cout << "***************************SEARCHING AGAIN*****************\n";
      retval = socket_active_processes_search ( socket_in, path_out, pid_out, ctmark_out );
    }
    return retval;
  }
  assert (false); //should never get here
}


//This cache of port<-->socket pairs is built in a loop by
//thread_build_pid_and_socket_cache
unsigned long is_port_in_cache (const int port, const int proto)
{
  pthread_mutex_t mutex;
  int *cache, *cache6;
  if (proto == PROTO_TCP){
    mutex = tcp_port_and_socket_cache_mutex;
    cache = tcp_port_and_socket_cache;
    cache6 = tcp6_port_and_socket_cache;
  }
  else if (proto == PROTO_UDP) {
    mutex = udp_port_and_socket_cache_mutex;
    cache = udp_port_and_socket_cache;
    cache6 = udp6_port_and_socket_cache;
  }

  int i = 0;
  int retval;
  _pthread_mutex_lock(&mutex);
  while (cache[i*2] != (unsigned long)MAGIC_NO) {
    if (i >= (MEMBUF_SIZE / (sizeof(unsigned long)*2)) - 1) break;
    if (cache[i*2] != port) {
      i++;
      continue;
    }
    _pthread_mutex_unlock(&mutex);
    return cache[i*2+1];
  }
  _pthread_mutex_unlock(&mutex);
  i = 0;
  while (cache6[i*2] != (unsigned long)MAGIC_NO) {
    if (i >= (MEMBUF_SIZE / (sizeof(unsigned long)*2)) - 1) break;
    if (cache6[i*2] != port) {
      i++;
      continue;
    }
    if (bTestingMode) assert(false);
    return cache6[i*2+1];
  }
  //socket wasn't found
  return -1;
}


void print_traffic_log(const int proto, const int direction, const string remotehost, const int lport,
               const int rport, const string path, const string pid, const int verdict)
{
  string m_logstring;
  string arrow;
  string proto_str;
  if (direction == DIRECTION_IN) {arrow = ">";}
  else if (direction == DIRECTION_OUT) {arrow = "<";}
  if (proto == PROTO_TCP)     {proto_str = "TCP ";}
  else if (proto == PROTO_UDP){proto_str = "UDP ";}
  else if (proto == PROTO_ICMP){proto_str = "ICMP ";}

  //only cast the first item to string(), no need to cast the rest
  m_logstring = arrow + proto_str + "remote " + remotehost+":"+to_string(rport) +
      " local " + to_string(lport) + " " + path + " " + pid + " ";

  switch ( verdict )
    {
    case SOCKET_FOUND_IN_DLIST_ALLOW:
    case PATH_FOUND_IN_DLIST_ALLOW:
    case NEW_INSTANCE_ALLOW:
    case FORKED_CHILD_ALLOW:
    case CACHE_TRIGGERED_ALLOW:
    case INKERNEL_RULE_ALLOW:
      m_logstring += "allow\n";
      break;
    case GLOBAL_RULE_ALLOW:
      m_logstring += "(global rule) allow\n";
      break;
    case CANT_READ_EXE:
      m_logstring += "(can't read executable file) drop\n";
      break;
    case SENT_TO_FRONTEND:
      m_logstring +=  "(asking frontend) drop\n";
      break;
    case SOCKET_FOUND_IN_DLIST_DENY:
    case PATH_FOUND_IN_DLIST_DENY:
    case NEW_INSTANCE_DENY:
    case FORKED_CHILD_DENY:
    case CACHE_TRIGGERED_DENY:
    case INKERNEL_RULE_DENY:
      m_logstring += "deny\n";
      break;
    case GLOBAL_RULE_DENY:
      m_logstring += "(global rule) deny \n";
      break;
    case SOCKET_NOT_FOUND_IN_PROCPIDFD:
      m_logstring +=  "(no process associated with socket) drop\n";
      break;
    case LOCALPORT_NOT_FOUND_IN_PROCNET:
      m_logstring +=  "(no socket associated with port) drop\n";
      break;
    case SOCKET_ACTIVE_PROCESSES_NOT_FOUND:
    //this verdict is triggered when on the first iteration of socket_active_processes_search()
    //socket was not found. Then it was found in socket_procpidfd_search()
    //and then on the second iteration of socket_active_processes_search(), it was not found again
      m_logstring +=  "(process exited while searching for socket) drop\n";
      break;
    case FRONTEND_NOT_LAUNCHED:
      m_logstring += "(frontend not active) drop\n";
      break;
    case FRONTEND_BUSY:
      m_logstring += "(frontend busy) drop\n";
      break;
    case UNSUPPORTED_PROTOCOL:
      m_logstring += "(unsupported protocol) drop\n";
      break;
    case ICMP_MORE_THAN_ONE_ENTRY:
      m_logstring += "More than one program is using icmp, dropping\n";
      break;
    case ICMP_NO_ENTRY:
      m_logstring += "icmp packet received by there is no icmp entry in /proc. Very unusual. Please report\n";
      break;
    case SHA_DONT_MATCH:
      m_logstring += "Red alert. Some app is trying to impersonate another\n";
      break;
    case SPOOFED_PID:
      m_logstring += "Attempt to spoof PID detected\n";
      break;
    case EXESIZE_DONT_MATCH:
      m_logstring += "Red alert. Executable's size don't match the records\n";
      break;
    case EXE_HAS_BEEN_CHANGED:
      m_logstring += "While process was running, someone changed his binary file on disk. Definitely an attempt to compromise the firewall\n";
      break;
    case SRCPORT_NOT_FOUND_IN_PROC:
      m_logstring += "(source port not found in procfs) drop\n";
      break;
    case INKERNEL_SOCKET_NOT_FOUND:
      m_logstring += "(no process associated with socket) drop\n";
      break;
    case INKERNEL_IPADDRESS_NOT_IN_DLIST:
      m_logstring += "(kernel process without a rule) drop\n";
      break;
    case SOCKET_ZERO_BUT_UID_NOT_ZERO:
      m_logstring += "(socket==0 but uid!=0) drop\n";
      break;
    case SOCKET_CHANGED_FROM_ZERO:
      m_logstring += "(socket changed from zero while we were scanning) drop\n";
      break;
    case PROCFS_ERROR:
      m_logstring += "(Couldn't find /proc/<pid>/stat entry) drop\n";
      break;
    default:
      m_logstring += "unknown verdict detected \n";
      printf ("verdict No %d \n", verdict);
      break;
    }
    cout << m_logstring;
}


//NOT IN USE
int socket_handle_icmp(int &ctmark_out, string &path_out,
                       string &pid_out, u_int64_t &stime_out)
{
  int retval;
  long socket;
  retval = icmp_check_only_one_socket ( &socket );
  if (retval != ICMP_ONLY_ONE_ENTRY) {return retval;}
  retval = socket_active_processes_search (socket, path_out, pid_out, ctmark_out );
  if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND) {return retval;}
  retval = socket_procpidfd_search (socket, path_out, pid_out, stime_out);
  if (retval != SOCKET_FOUND_IN_PROCPIDFD) {return retval;}
  retval = path_find_in_rules (ctmark_out, path_out, pid_out, stime_out, true);
  return retval;
}


//Not in use
int inkernel_get_verdict(const char *ipaddr_in, int &ctmark_out) {
  _pthread_mutex_lock ( &rules_mutex );
  for(int i = 0; i < rules.size(); i++){
    if (rules[i].path == KERNEL_PROCESS) continue;
    if (rules[i].pid != ipaddr_in) continue;
    if (rules[i].perms == ALLOW_ALWAYS || rules[i].perms == ALLOW_ONCE) {
      rules[i].is_active = true;
      ctmark_out = rules[i].ctmark_out;
      _pthread_mutex_unlock(&rules_mutex);
      return INKERNEL_RULE_ALLOW;
    }
    else if (rules[i].perms == DENY_ALWAYS || rules[i].perms == DENY_ONCE) {
      _pthread_mutex_unlock(&rules_mutex);
      return INKERNEL_RULE_DENY;
    }
  }
  _pthread_mutex_unlock(&rules_mutex);
  return INKERNEL_IPADDRESS_NOT_IN_DLIST;
}


int send_request (const string path, const string pid, const string starttime,
             const string raddr, const string rport, const string lport, const int direction) {
  set_awaiting_reply_from_fe(true);
  string req;
  if (direction == DIRECTION_OUT) {req = "REQUEST_OUT ";}
  else if (direction == DIRECTION_IN) {req = "REQUEST_IN ";}
  string b64path = base64_encode(
            reinterpret_cast<const unsigned char*>(path.c_str()), path.length());
  requestQueue.push(req + b64path + " " + pid + " " + starttime +
                  " " + raddr + " " + rport + " " + lport + " EOL ");
  return SENT_TO_FRONTEND;
}


int send_rules() {
  _pthread_mutex_lock ( &rules_mutex );
  string message = "RULES_LIST ";
  for(int k=0; k < rules.size(); k++){
    string is_active = rules[k].is_active ? "TRUE": "FALSE";
    string b64path = base64_encode(
          reinterpret_cast<const unsigned char*>(rules[k].path.c_str()), rules[k].path.length());
    message += b64path + " " + rules[k].pid + " " + rules[k].perms + " "
        + is_active + " " + to_string(rules[k].ctmark_out) + " CRLF ";
  }
  message += " EOL ";
  rulesListQueue.push(message);
  _pthread_mutex_unlock ( &rules_mutex );
}


//All connections (both incoming and outgoing end up here)
int nfq_handle ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfad, void *thread_data ) {

  //For simplicity, we do not allow this function to be run concurrently
  static pthread_mutex_t nfq_handle_mutex = PTHREAD_MUTEX_INITIALIZER;
  _pthread_mutex_lock(&nfq_handle_mutex);
  //Update timer for last packet seen
  _pthread_mutex_lock(&lastpacket_mutex);
  gettimeofday(&lastpacket, NULL);
  _pthread_mutex_unlock(&lastpacket_mutex);
  int direction = *((int *)(thread_data));
  //there's no need to free(thread_data)

  //Extract IP packet payload
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
  if (!ph) { die("ph == NULL, should never happen, please report"); }
  u_int32_t id = ntohl ( ph->packet_id );
  struct iphdr *ip;
  nfq_get_payload ( ( struct nfq_data * ) nfad, (unsigned char**)&ip );
  int proto = ip->protocol;

  //remote addr and local addr
  char raddr[INET_ADDRSTRLEN], laddr[INET_ADDRSTRLEN];
  if (direction == DIRECTION_OUT){
    inet_ntop(AF_INET, &(ip->daddr), raddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->saddr), laddr, INET_ADDRSTRLEN);
  }
  if (direction == DIRECTION_IN){
    inet_ntop(AF_INET, &(ip->daddr), laddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->saddr), raddr, INET_ADDRSTRLEN);
  }
  if (!bTestingMode && string(laddr) == string(raddr)){
    //During testing we send traffic from our external interface client to
    //our external interface server. Disable this check
    //This is local traffic, we should not do anything with it
    //Investigate if attacker can give a fake src addr
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
    _pthread_mutex_unlock(&nfq_handle_mutex);
    return 0;
  }

  int verdict;
  string path = "";
  string pid = "";
  string proto_str = "";
  string proto6_str = "";
  u_int64_t starttime;
  int ctmark;

  cout << "nfq_handle - raddr: " << raddr << " laddr:" << laddr << "\n";

  // ihl field is IP header length in 32-bit words, multiply by 4 to get length in bytes
  u_int16_t lport_netbo, rport_netbo, lport_hostbo, rport_hostbo, sport, dport;
  if (proto == PROTO_TCP) {
    struct tcphdr *tcp = ( struct tcphdr* ) ((char*)ip + ( 4 * ip->ihl ) );
    //we need sport/dport regardless of direction for conntrack purposes later
    sport = tcp->source;
    dport = tcp->dest;
    if (direction == DIRECTION_OUT){
      lport_netbo = tcp->source;
      rport_netbo = tcp->dest;
      lport_hostbo = ntohs ( tcp->source );
      rport_hostbo = ntohs ( tcp->dest );
    }
    if (direction == DIRECTION_IN){
      rport_netbo = tcp->source;
      lport_netbo = tcp->dest;
      rport_hostbo = ntohs ( tcp->source );
      lport_hostbo = ntohs ( tcp->dest );
    }
    proto_str = "TCP";
    proto6_str = "TCP6";
  }
  else if (proto == PROTO_UDP) {
    struct udphdr *udp = ( struct udphdr * ) ( (char*)ip + ( 4 * ip->ihl ) );
    //we need sport/dport regardless of direction for conntrack purposes later
    sport = udp->source;
    dport = udp->dest;
    if (direction == DIRECTION_OUT){
      lport_netbo = udp->source;
      rport_netbo = udp->dest;
      lport_hostbo = ntohs ( udp->source );
      rport_hostbo = ntohs ( udp->dest );
    }
    if (direction == DIRECTION_IN){
      rport_netbo = udp->source;
      lport_netbo = udp->dest;
      rport_hostbo = ntohs ( udp->source );
      lport_hostbo = ntohs ( udp->dest );
    }
    proto_str = "UDP";
    proto6_str = "UDP6";
  }
  else {
    cout << "unknown protocol, dropping packet " << proto << "\n";
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
    _pthread_mutex_unlock(&nfq_handle_mutex);
    return 0;
  }

  //Knowing only the local port, find full path of the process
  unsigned long socket_found;
  if ((socket_found = is_port_in_cache(lport_hostbo, proto)) == -1){
    cout << "socket not found in cache \n";
    if (build_port_and_socket_cache(socket_found, laddr, lport_hostbo, raddr,
                                    rport_hostbo, proto_str, direction) == 0) {
      //maybe it was IPv6 socket
      if (build_port_and_socket_cache(socket_found, laddr, lport_hostbo, raddr,
                                      rport_hostbo, proto6_str, direction) == 0) {
            verdict = LOCALPORT_NOT_FOUND_IN_PROCNET;
            goto execute_verdict;
      }
    }
  }
  assert (socket_found > 0);
  bool fe_was_busy;

  //in-kernel socket check not in use for now
//  if (socket_found == 0){
//    verdict = inkernel_check(lport_hostbo, proto);
//    if (verdict == INKERNEL_SOCKET_FOUND) {
//      verdict = inkernel_get_verdict(raddr, ctmark);
//    }
//    else { goto execute_verdict; }
//  }

  fe_was_busy = awaiting_reply_from_fe;
  verdict = socket_handle (socket_found, ctmark, path, pid, starttime, lport_hostbo );
  if (verdict == PATH_IN_RULES_NOT_FOUND || verdict == PATH_IN_RULES_FOUND_BUT_PERMS_ARE_ONCE){
    if (! bFrontendActive) { verdict = FRONTEND_NOT_LAUNCHED; }
    else if (fe_was_busy) { verdict = FRONTEND_BUSY; }
    else if (awaiting_reply_from_fe) { verdict = FRONTEND_BUSY; }
    else {
      //frontend IS now not busy and WAS not busy when we started socket_handle_tcp_out
      //There was a small window when we were inside socket_handle_out
      //for the frontend to respond. So, we double-check that the path
      //we are about to query was not added to the rules during that small window
      verdict = path_find_in_rules (ctmark, path, pid, starttime, true);
      if (verdict == PATH_IN_RULES_NOT_FOUND || verdict == PATH_IN_RULES_FOUND_BUT_PERMS_ARE_ONCE) {
        verdict = send_request(path, pid, to_string(starttime), string(raddr),
                             to_string(lport_hostbo), to_string(rport_hostbo), direction);
      }
      else {
        die("if (verdict == PATH_IN_RULES_NOT_FOUND");
      }
    }
  }
execute_verdict:
  print_traffic_log(proto, direction, string(raddr), lport_hostbo, rport_hostbo,
                    path, pid, verdict);

  if (direction == DIRECTION_OUT){
    ctmark_to_set = ctmark;}
  else if (direction == DIRECTION_IN){
    ctmark_to_set = ctmark + CTMARK_DELTA;}

  if (verdict < ALLOW_VERDICT_MAX) {
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );

    //create a new conntrack object
    nf_conntrack *nf_ct = _nfct_new();
    nfct_set_attr_u32(nf_ct, ATTR_ORIG_IPV4_DST, ip->daddr);
    nfct_set_attr_u32(nf_ct, ATTR_ORIG_IPV4_SRC, ip->saddr);
    nfct_set_attr_u8 (nf_ct, ATTR_L4PROTO, ip->protocol);
    nfct_set_attr_u8 (nf_ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u16(nf_ct, ATTR_PORT_SRC, sport);
    nfct_set_attr_u16(nf_ct, ATTR_PORT_DST, dport) ;
    //query if this object exists and if it does, setmark_handle will set the mark
    while (nfct_query(setmark_handle, NFCT_Q_GET, nf_ct) == -1) {
      if (errno == EBUSY) {
          //EBUSY returned, when there's too much activity in conntrack. Requery the packet
          cout << "nfct_query GET error: " << strerror(errno) << "\n";
          break;
      }
      else if (errno == EILSEQ) {
          cout << "nfct_query GET error: " << strerror(errno) << "\n";
          break;
      }
      else{
          cout << "nfct_query GET error: " << strerror(errno) << "\n";
          break;
      }
    }
    nfct_destroy(nf_ct);
  } //if (verdict < ALLOW_VERDICT_MAX)
  else if (verdict < DENY_VERDICT_MAX) {
    denied_traffic_add (direction, ctmark_to_set, ip->tot_len );
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
  }
  else{
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
  }
  _pthread_mutex_unlock(&nfq_handle_mutex);
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
      ifstream comm_path("/proc/" + pid_str + "/comm");
      string exe_name;
      getline(comm_path, exe_name);
      if (exe_name == "lpfw" && ( pid_t ) pid_int != getpid()){
        cout << "lpfw is already running \n";
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
  cout << "Removing pidfile and flushing netfilter. Bye." << "\n";
  _remove ( pid_file->filename[0] );
  //release netfilter_queue resources
  _nfq_close ( globalh_out );
  //remove iptables  rules
  _system ("iptables -F");
  exit(0);
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
        printf ( "%s\n", "0.6" );
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
  _fputs ("full_path=        ", rulesfile_stream);
  _fputs (exefile_path, rulesfile_stream);
  _fputc ('\n', rulesfile_stream);
  _fputs ("permission=       ", rulesfile_stream);
  _fputs (ALLOW_ALWAYS, rulesfile_stream);
  _fputc ('\n', rulesfile_stream);
  _fputs ("sha256_hexdigest= ", rulesfile_stream);
  _fputs (sha.c_str(), rulesfile_stream);
  _fputc ('\n', rulesfile_stream);
  _fclose (rulesfile_stream);
}


//Check that capabilities are permitted and clear all other capabilities
//except for the ones we need
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

  _cap_clear(cap_current);
  const cap_value_t caps_list[] = {CAP_SYS_PTRACE, CAP_NET_ADMIN, CAP_DAC_READ_SEARCH};
  _cap_set_flag(cap_current, (cap_flag_t)CAP_PERMITTED, 3, caps_list, (cap_flag_value_t)CAP_SET);
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
  capabilities_modify(CAP_SETUID, CAP_EFFECTIVE, CAP_CLEAR);
}

void setup_signal_handlers()
{
    //install SIGTERM handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = SIGTERM_handler;
    if ( sigaction ( SIGTERM, &sa, NULL ) == -1 ){
      perror ( "sigaction" );
    }
    if ( sigaction ( SIGINT, &sa, NULL ) == -1 ){
      perror ( "sigaction" );
    }
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
  _system ("iptables -F INPUT");
  _system ("iptables -F OUTPUT");
  string gid_match = ""; //not in use in normal (non-testing) mode
  if (bTestingMode) { gid_match= "-m owner --gid-owner lpfwtest"; }
  _system (string("iptables -I OUTPUT 1 -m state --state NEW " +
                  gid_match + " -j NFQUEUE --queue-num 11220").c_str());
  //owner match doesn't work with INPUT hooks
  //During testing we create a per-port iptables rules for each test server listening port
  //That's why we start off with no INPUT rules in testing
  if (!bTestingMode) {
    _system ("iptables -I INPUT 1 -m state --state NEW -j NFQUEUE --queue-num 11221");
  }
  //using /mask caused 10+ second lag when calling iptables
  //_system ("iptables -I OUTPUT 1 -d 127.0.0.0/8 -j ACCEPT");
  //_system ("iptables -I INPUT 1 -d 127.0.0.0/8 -j ACCEPT");
  _system ("iptables -I OUTPUT 1 -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT");
  _system ("iptables -I INPUT 1 -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT");


  //save and start checking if iptables rules altered
  pthread_t iptables_check;
  char save_output[MAX_LINE_LENGTH] = "iptables -L OUTPUT > ";
  char save_input[MAX_LINE_LENGTH] = "iptables -L INPUT >";
  strcat (save_output, SAVE_IPTABLES_OUTPUT_FILE);
  strcat (save_input, SAVE_IPTABLES_INPUT_FILE);
  _system (save_output);
  _system (save_input);
  //_pthread_create ( &iptables_check, (pthread_attr_t *)NULL, iptables_check_thread, (void *)NULL);
}


void init_nfqueue()
{
  struct nfq_q_handle * globalqh_out, * globalqh_input;
  //-----------------Register OUT queue handler-------------
  globalh_out = _nfq_open();
  _nfq_unbind_pf (globalh_out, AF_INET );
  _nfq_bind_pf (globalh_out, AF_INET );
  int *out_data = (int *)malloc(sizeof(int));
  *out_data = DIRECTION_OUT;
  globalqh_out = _nfq_create_queue (globalh_out, NFQNUM_OUT,
                                    &nfq_handle, (void*)out_data );
  //copy only 40 bytes of packet to userspace - just to extract tcp/udp source field
  _nfq_set_mode (globalqh_out, NFQNL_COPY_PACKET, 40 );
  _nfq_set_queue_maxlen (globalqh_out, 200 );
  int *nfqfd_out = (int *)malloc(sizeof(int));
  *nfqfd_out = nfq_fd ( globalh_out);

  //-----------------Register IN queue handler-------------
  globalh_in = _nfq_open();
  _nfq_unbind_pf (globalh_in, AF_INET );
  _nfq_bind_pf (globalh_in, AF_INET );
  int *in_data = (int *)malloc(sizeof(int));
  *in_data = DIRECTION_IN;
  globalqh_input = _nfq_create_queue (globalh_in, NFQNUM_INPUT,
                    &nfq_handle, (void*)in_data );
  //copy only 40 bytes of packet to userspace - just to extract tcp/udp source field
  _nfq_set_mode (globalqh_input, NFQNL_COPY_PACKET, 40 );
  _nfq_set_queue_maxlen (globalqh_input, 200 );
  int *nfqfd_in = (int *)malloc(sizeof(int));
  *nfqfd_in = nfq_fd ( globalh_in);

  //the threads will end up calling nfq_handle()
  _pthread_create ( &nfq_in_thr, (pthread_attr_t *)NULL, thread_nfq_in, (void *)nfqfd_in);
  _pthread_create ( &nfq_out_thr, (pthread_attr_t *)NULL, thread_nfq_out, (void *)nfqfd_out);
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


//Not in use. Obsolete but left here for reference
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
  struct rlimit core_limit; //limit for the core file size
  core_limit.rlim_cur = RLIM_INFINITY;
  core_limit.rlim_max = RLIM_INFINITY;
  struct rlimit of_limit; //open file limit
  of_limit.rlim_cur = 500000;
  of_limit.rlim_max = 500000;
  if(setrlimit(RLIMIT_CORE, &core_limit) < 0){
  printf("setrlimit: %s\nWarning: core dumps may be truncated or non-existant\n", strerror(errno));}
  if(setrlimit(RLIMIT_NOFILE, &of_limit) < 0){
  printf("setrlimit: %s\nWarning: could not increase open file limit\n", strerror(errno));}

  if (argc == 2 && ( !strcmp(argv[1], "--help") || !strcmp(argv[1], "--version"))){
      parse_command_line(argc, argv);
      return 0;
  }

  capabilities_setup();
  //setuid_root();
  //setgid_lpfwuser();
  if (prctl(PR_SET_DUMPABLE, 1) == -1){ perror("prctl SET_DUMPABLE"); }
  setup_signal_handlers();

  parse_command_line(argc, argv);
  if (test->count == 1) bTestingMode = true;
  init_log();
  pidfile_check();
  if (!bTestingMode) {
    rules_load();
  }
  open_proc_net_files();

  capabilities_modify(CAP_NET_ADMIN, CAP_EFFECTIVE, CAP_SET);
  init_conntrack();
  init_iptables();
  capabilities_modify(CAP_DAC_READ_SEARCH, CAP_EFFECTIVE, CAP_SET);
  capabilities_modify(CAP_SYS_PTRACE, CAP_EFFECTIVE, CAP_SET);
  init_nfqueue();

  _pthread_create ( &refresh_thr, (pthread_attr_t *)NULL, thread_refresh, (void *)NULL );
  _pthread_create ( &cache_build_thr, (pthread_attr_t *)NULL, thread_build_pid_and_socket_cache, (void *)NULL);
  _pthread_create ( &tcp_server_thr, (pthread_attr_t *)NULL, thread_tcp_server,(void *)NULL);
  if (bTestingMode) {
    _pthread_create ( &test_thr, (pthread_attr_t *)NULL, thread_test,(void *)NULL);
  }

  while(true){sleep(10);}
}
