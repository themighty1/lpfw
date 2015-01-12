#ifndef LPFW_H
#define LPFW_H

#include <pthread.h>
#include "common/defines.h"
#include "common/includes.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h> // for FILE*
using namespace std;

//PID of currently active frontend
extern pid_t fe_pid;
//Pointer to function which does the logging
extern int (*m_printf)(const int loglevel, const char *logstring);
//enables other files to use the logging facility
extern pthread_mutex_t logstring_mutex;
extern char logstring[PATHSIZE];

//add a new rule and if ctmark is not specified, return a new ctmark for the newly added rule
int ruleslist_add ( const char *path, const char *pid, const char *perms, const bool current, const char *sha,
    const unsigned long long stime, const off_t size, const int ctmark, const unsigned char first_instance );

//remove rule from ruleslist
void ruleslist_delete_one ( const char *path, const char *pid );

//builds correlation tables between ports and sockets for variour /proc/net/* files and at the same time
//checks if port_to_find is in the table. Returns socket corresponding to port_to_find or -1
//if port_to_find was not found
int build_tcp_port_and_socket_cache(long &socket_out, const int port_in);
int build_tcp6_port_and_socket_cache(long &socket_out, const int port_in);
int build_udp_port_and_socket_cache(long &socket_out, const int port_in);
int build_udp6_port_and_socket_cache(long &socket_out, const int port_in);
//returns socket corresponding to port or -1 if not found
unsigned long is_port_in_cache(const int port, const int proto);
unsigned long is_udp_port_in_cache(const int port);

//print logstring to the preffered logging facility. A pointer to one of these functions is assigned
//to m_printf
int m_printf_stdout ( const int loglevel, const char * logstring );
int m_printf_file ( const int loglevel, const char * logstring );
int m_printf_syslog (const int loglevel, const char * logstring);

//find socket in pid_and_socket cache of active rules only and return path,pid,ctmark if found
int search_pid_and_socket_cache(const long socket_in, string &path_out,
                                    string &pid_out, int &ctmark_out);
//build a correlation of pid to socket of only the active rules, excluding inkernel rules
void* thread_build_pid_and_socket_cache ( void *ptr );

//thread-safe getter and setter for fe_active_flag
int fe_active_flag_get();
void fe_active_flag_set (const unsigned char boolean);

//threads which receive packets from NFQUEUE and call handlers on those pakets
//NB nfq_out_tcp loop is at the end of main()
void* thread_nfq_in ( void *ptr );
void* thread_nfq_out ( void *ptr );

//handlers for NFQUEUE traffic
int  nfq_handle ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );

//find the process which owns the socket and return ctmark,path,pid,stime, otherwise SOCKET_NOT_FOUND_IN_PROCPIDFD
int socket_handle ( const long *socket, int *ctmark_to_set, char *path, char *pid, u_int64_t *stime);

//determine if port belongs to a in-kernel process. Kernel modules can open sockets but the have no PID
int inkernel_check_udp(const int port);
int inkernel_check(const int port, const int proto);
//if in-kernel socket found, see if there is a rule for it already
int inkernel_get_verdict(const char *ipaddr_in, int &ctmark_out);

//SET/CLEAR capability of a set
void capabilities_modify(const int capability, const int set, const int action);

//Get pid's starttime
unsigned long long starttimeGet ( const int pid );

//check which active rules are still running and remove them if they are not running anymore
void* thread_refresh ( void* ptr );

//process rules.conf
void global_rule_add( const char *str_direction, char *str_ports);
void rules_load();
void rules_write(bool mutex_being_held = false);
void add_to_rulesfile( const char *executable);

//chack if path+pid combo is already in ruleslist
int path_find_in_rules (int &ctmark_out, const string path_in,
                            const string pid_in, unsigned long long stime_in, bool going_out);

//search socket in /proc/<PID>/fd of the active rules
int socket_active_processes_search (const long mysocket_in, string &m_path_out, string &m_pid_out, int &ctmark_out);

//search socket in the whole of /proc/<PID>s
int socket_procpidfd_search (const long mysocket_in, char *m_path_out, char *m_pid_out, u_int64_t stime_out );

//if there's >1 entry in /proc/net/raw for icmp, it's impossible to tell which process is sending the packet
int icmp_check_only_one_socket ( long *socket );

//contruct a string to print to logging facility
void print_traffic_log(const int proto, const int direction, const string ip, const int srcport,
               const int dstport, const string path, const string pid, const int verdict);

//setup logging facility
void init_log();

void pidfile_check();
void setup_signal_handlers();
void SIGTERM_handler ( int signal );
int parse_command_line(int argc, char* argv[]);

// chack that we have the needed capabilities and if we do, then drop all the other capabilities
void capabilities_setup();

// Create group lpfwuser. Backend and frontend both should belong to this group to communicate over IPC
void setgid_lpfwuser();

// uid == 0. It is not full-fledged root because it has stripped capabilities
void setuid_root();
void init_iptables();
void* iptables_check_thread (void *ptr);
void init_nfqueue();
void init_ruleslist();
void open_proc_net_files();
void init_conntrack();

// USED FOR TESTING AND DEBUGGING
int port2socket_udp ( int *portint, int *socketint );
int port2socket_tcp ( int *portint, int *socketint );
//dump all rules to a files
void* rules_dump_thread ( void *ptr );

extern void* thread_test ( void *ptr ); //from testmain.cpp
int send_request(const string path, const string pid, const string starttime,
             const string raddr, const string rport, const string lport, const int direction);
string get_sha256_hexdigest(string exe_path);

#endif // LPFW_H
