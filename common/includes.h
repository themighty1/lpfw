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


string rulesfile_header = "\n"
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
