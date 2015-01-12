#ifndef INCLUDES_H_
#define INCLUDES_H_

#include "defines.h"
#include <unistd.h>
#include <sys/types.h> //for ino_t
#include <dirent.h> //for DIR*
#include <netinet/ip.h> //for INET_ADDRSTRLEN
#include <pthread.h>
#include <string>
#include <vector>
using namespace std;

void die_syscall(string message);

//macros enables any thread to use logging concurrently
#define M_PRINTF(loglevel, ...) \
    //pthread_mutex_lock(&logstring_mutex);
    //cout << "LOG:" << logstring << "\n";
    //pthread_mutex_unlock(&logstring_mutex);


struct rule{
  string path; //path to executable
  string pid; //its pid (or IP address for kernel processes)
  string perms; // permission in the form "ALLOW ALWAYS"
  string sha; //sha256 hexdigest
  u_int32_t ctmark_out;
  u_int32_t ctmark_in; //conntrack mark assigned to each new connection
  //and used when a user deletes a rule to tell conntrack to immediately
  //drop any existing connections associated with the mark
  bool is_active; //Has process already been seen sending/receiving packets?
  bool first_instance; //TRUE for a first instance of an app or a parent process (not in use?)
  bool is_fixed_ctmark = false; //the user may assign a fixed netfilter mark for conntrack purposes
  unsigned long long stime; // start time of the process
  vector<long> sockets;//sockets owned by the processes
  string pidfdpath; //path to /proc/PID/fd
  DIR *dirstream; //a constantly open stream to /proc/PID/fd
};


enum
{
  SOCKET_FOUND_IN_DLIST_ALLOW,
  PATH_FOUND_IN_DLIST_ALLOW,
  NEW_INSTANCE_ALLOW,
  FORKED_CHILD_ALLOW,
  CACHE_TRIGGERED_ALLOW,
  INKERNEL_RULE_ALLOW, //5
  GLOBAL_RULE_ALLOW,
  ALLOW_VERDICT_MAX,

  SOCKET_FOUND_IN_DLIST_DENY,
  PATH_FOUND_IN_DLIST_DENY,
  NEW_INSTANCE_DENY, //10
  FORKED_CHILD_DENY,
  CACHE_TRIGGERED_DENY,
  INKERNEL_RULE_DENY,
  GLOBAL_RULE_DENY,
  DENY_VERDICT_MAX, //15

  GLOBAL_RULES_VERDICT_MAX,

  SENT_TO_FRONTEND,
  FRONTEND_NOT_LAUNCHED,
  FRONTEND_BUSY,
  ICMP_MORE_THAN_ONE_ENTRY, //20
  ICMP_NO_ENTRY,
  ICMP_ONLY_ONE_ENTRY,
  UNSUPPORTED_PROTOCOL,
  SHA_DONT_MATCH,
  EXESIZE_DONT_MATCH, //25 (not in use)
  EXE_HAS_BEEN_CHANGED,
  CANT_READ_EXE,
  SPOOFED_PID,
  PROCFS_ERROR,
  INKERNEL_SOCKET_FOUND, //30
  INKERNEL_SOCKET_NOT_FOUND,
  INKERNEL_IPADDRESS_NOT_IN_DLIST,
  SRCPORT_NOT_FOUND_IN_PROC, //not in use
  DSTPORT_NOT_FOUND_IN_PROCNET,
  SOCKET_NOT_FOUND_IN_PROCPIDFD, //35
  SOCKET_FOUND_IN_PROCPIDFD,
  //SRCPORT_NOT_FOUND_IN_PROCNET happens when a process connect()s in non-blocking mode
  //and immediately closes the socket. Or when so many new connections happen simultaneously
  //that there is a lag in connection appearing in /proc/net/*
  LOCALPORT_NOT_FOUND_IN_PROCNET,
  SOCKET_IN_CACHE_NOT_FOUND,
  PATH_IN_RULES_NOT_FOUND,
  PATH_IN_RULES_FOUND_BUT_PERMS_ARE_ONCE, //40
  SOCKET_ACTIVE_PROCESSES_NOT_FOUND,
  GID_MATCH_ALLOW,
  GID_MATCH_DENY,
  SOCKET_ZERO_BUT_UID_NOT_ZERO,
  SOCKET_CHANGED_FROM_ZERO, //45
  SEARCH_ACTIVE_PROCESSES_AGAIN,
  PROCPIDSTAT_DOES_NOT_EXIST
};



#endif /* INCLUDES_H_ */
