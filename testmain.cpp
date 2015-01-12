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
#include <string.h> //for strerror()
#include <linux/netfilter.h> //for NF_ACCEPT, NF_DROP etc. This sucker has to go to the bottom,

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <cassert>
#include <time.h>

#include <fstream>
#include <map>
#include <ctime>
#include <algorithm>
#include <string>
#include <vector>
#include <sstream>

//otherwise you'll get compile errors
#include "common/includes.h"
#include "common/syscall_wrappers.h"

typedef map<string, string> procmap;

using namespace std;

extern vector<string> split_string(string input, string delimiter=" ");
extern pthread_mutex_t rules_mutex;
extern vector<rule> rules;
extern bool awaiting_reply_from_fe;
extern int ruleslist_add( const string path, const string pid, const string perms,
                          const bool active, const string sha, const unsigned long long stime,
                          const int nfmark, const bool first_instance);
string test_frontend_request = ""; //global var used to make sure the frontend receives
//correct request strings
string test_verdict; //global var to tell frontend which verdict to pass
map <string, map <string, string> > test_requests; //maps PID to a request
//which is about to be sent to the frontend. Used to check request formatting
string iface_str;
int local_tcp_echo_port;
int local_udp_echo_port;
void *tcp_server (void *ptr);
void *udp_server (void *ptr);
bool localtest = false; //whether to send data to local server (for testing offline) or to web servers

extern void die(string message);


typedef struct {
    int qfd;
    struct nfq_handle *handle;
} thread_args;


int current_seconds(){
  time_t t = time(0);   // get time now
  struct tm * now = localtime( & t );
  return now->tm_sec;
}

bool fileExists(const std::string& filename)
{
    struct stat buf;
    if (stat(filename.c_str(), &buf) != -1)
    {
        return true;
    }
    return false;
}

//Not in use
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

//Not in use
int handle_packet ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfad, void *mdata ) {
  struct iphdr *ip;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
  if ( !ph ) { die ("ph == NULL, should never happen, please report"); }
  u_int32_t id = ntohl ( ph->packet_id );
  nfq_get_payload ( ( struct nfq_data * ) nfad, (unsigned char**)&ip );
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

//Not in use
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
  char *arg = (char *)calloc(strlen(commline.c_str())+1, 1);
  strncpy(arg, commline.c_str(), strlen(commline.c_str()));
  _pthread_create (&thr_newprocess, (pthread_attr_t*)NULL, thread_newprocess, arg);
}


void* frontend_thread(void *data){
  int sockfd, n;
  char buffer[8192*64];

  int daemon_port = 0;
  string port_str;
  ifstream portfile("/tmp/commport");
  getline(portfile, port_str);
  portfile.close();
  daemon_port = stoi(port_str);
  assert (daemon_port != 0);

  struct sockaddr_in serv_addr;
  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) { die("socket() failed"); }
  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(daemon_port);
  if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) { die("inet_pton() failed"); }
  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
      die("connect() to backend failed");
  }
  ofstream f("/tmp/lpfwtest/frontend-is-ready");
  f.close();
  cout << "testfrontend listening" << "\n";
  while (true){
    bzero(buffer,8192);
    n = read(sockfd,buffer,8192);
    if (n < 0) {//no data
      sleep(1);
      continue;
    }
    cout << "frontend received:" << buffer << "\n";
    cout << "Received at:" << current_seconds() << "\n";
    string data(buffer);
    if (data.substr(0,7) != "REQUEST_OUT"){
      continue;
    }
    vector<string> data_parts = split_string(data);
    if (data_parts[0]=="REQUEST_OUT") {
      assert (strstr(data_parts[1].c_str(), "/tmp/lpfwtest/testprocess") != NULL);
      test_frontend_request = data;
      string path = data_parts[1];
      string pid = data_parts[2];
      string starttime = data_parts[3];
      string host = data_parts[4];
      string remoteport = data_parts[5];
      string localport = data_parts[6];

      if (test_requests.count(pid) != 1) {
        cout << "Unexpected pid in request \n";
        exit(1);
      }
      map <string, string> match = test_requests.at(pid);
      test_requests.erase(pid);

      if (match["path"] != path || match["starttime"] != starttime || match["host"] != host ||
          match["localport"] != localport ){
          //|| match["remoteport"] != remoteport){ //TODO figure out remoteport for localservers
        cout << "Unexpected REQUEST in frontend \n";
        abort();
        exit(1);
      }
      string perms = match["perms"];
      string response = "ADD " + path + " " + pid + " " + perms;
      if (send(sockfd, response.c_str(), response.length(), MSG_NOSIGNAL) < 0) {
        cout << "ERROR writing to socket";
        _close(sockfd);
        return 0;
      }
    }
    else { continue; }
  }
}


void create_lpfwtest_group()
{
  gid_t lpfwtest_gid;
  //check existence of lpfwtest group
  errno = 0;
  struct group *m_group;
  m_group = getgrnam("lpfwtest");
  if (!m_group){
    if (errno == 0){
      printf("lpfwtest group does not exist, creating...\n");
      _system("groupadd lpfwtest");
      //get group id again after group creation
      errno = 0;
      m_group = getgrnam("lpfwtest");
      if(!m_group){
        if (errno == 0){
          printf ("lpfwtest group still doesn't exist even though we've just created it");
        }
        else{
          perror ("getgrnam");
        }
      }
      lpfwtest_gid = m_group->gr_gid;
    }
    else{
      printf("Error in getgrnam\n");
      perror ("getgrnam");
    }
  }
}


//optionally return true a false depending on if file was found
bool wait_for_semaphore_file(string path, bool bShouldReturn = false){
  struct timespec refresh_timer,dummy;
  refresh_timer.tv_sec=0;
  refresh_timer.tv_nsec=1000000000/100;
  int loops = 0;
  while (true) {
    if (fileExists(path)){
      return true;
    }
    //else file does not yet exist
    ++loops;
    if (loops > 700){
      if (bShouldReturn){
        return false;
      }
      else {
        die("Timeout waiting on the semaphore file " + path);
      }
    }
    while(nanosleep(&refresh_timer, &refresh_timer));
  }
}


//starts a new process and returns its random ID and PID
//the process is listening on further commands
procmap new_process(){
  char *temppath = get_current_dir_name();
  string cwd(temppath);
  free(temppath);
  string cp_src = "cp " + cwd + "/testprocess ";
  string cp_dst = "/tmp/lpfwtest/testprocess";
  string random_str = to_string(rand());
  _system(string(cp_src + cp_dst + random_str).c_str());

  string commline(cp_dst + random_str + " " + random_str);
  pthread_t thr_newprocess;
  char *arg = (char *)calloc(strlen(commline.c_str())+1, 1);
  strncpy(arg, commline.c_str(), strlen(commline.c_str()));
  _pthread_create (&thr_newprocess, (pthread_attr_t*)NULL, thread_newprocess, arg);

  wait_for_semaphore_file("/tmp/lpfwtest/"+random_str+".pid-file-is-ready");
  string pid_str;
  ifstream pidfile("/tmp/lpfwtest/"+random_str+".pid");
  getline(pidfile, pid_str);
  pidfile.close();
  assert (pid_str != "");
  procmap retval;
  retval["randID"] = random_str;
  retval["PID"] = pid_str;
  retval["path"] = cp_dst + random_str;
  retval["firstinstance"] = "true";
  return retval;
}


void issue_command(procmap proc, string command){
  string randID = proc["randID"];
  wait_for_semaphore_file("/tmp/lpfwtest/"+randID+".ready-to-receive-commands");
  ofstream f("/tmp/lpfwtest/"+randID+".command");
  f << command;
  f.close();
  remove(string("/tmp/lpfwtest/"+randID+".ready-to-receive-commands").c_str());
  ofstream fready("/tmp/lpfwtest/"+randID+".command-file-is-ready");
  fready.close();
}


string get_port_number(procmap proc){
  string randID = proc["randID"];
  string proto = proc["proto"];
  string suffix;
  string port;
  wait_for_semaphore_file("/tmp/lpfwtest/"+randID+".port-file-is-ready");
  if (proto == "TCP") {suffix = ".tcp";}
  else if (proto == "UDP") {suffix = ".udp";}
  else {abort();}
  ifstream portfile("/tmp/lpfwtest/" + randID + suffix);
  getline(portfile, port);
  portfile.close();
  assert (port != "");
  return port;
}


//adapted from lpfw.cpp
string starttimeGet (procmap proc) {
  string mypid = proc["PID"];
  unsigned long long starttime;
  FILE *stream;
  string path("/proc/" + mypid + "/stat");
  stream = _fopen (path.c_str(), "r" );
  fscanf ( stream, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s"
           "%*s %*s %*s %*s %*s %*s %*s %llu", &starttime );
  _fclose ( stream );
  return to_string(starttime);
}


//Return the specified amount of new processes bound to local sockets
vector<procmap> new_processes(int amount, string mode, string proto){
  vector<procmap> retprocs;
  for (int i=0; i<amount; ++i){
      procmap proc = new_process();
      if (mode == "client"){
        issue_command(proc, "client");
        if (proto == "TCP"){
          issue_command(proc, "bind_tcp_client");
        }
        else if (proto == "UDP"){
          issue_command(proc, "bind_udp_client");
        }
      }
      else if (mode == "server"){
        if (proto == "TCP"){
          issue_command(proc, "localtcpserver");
        }
        else if (proto == "UDP"){
          issue_command(proc, "localudpserver");
        }
      }
      else { cout << "error\n"; exit(1);}

      proc["proto"] = proto;
      proc["starttime"] = starttimeGet(proc);
      proc["mode"] = mode;
      proc["localport"] = get_port_number(proc);
      retprocs.push_back(proc);
  }
  return retprocs;
}


//Tells frontend to expect a certain request. Test frontend also check request formatting
//Also adds new items to proc
//The process is supposed to be bound to local port at this point
void expect_request(procmap &proc, string perms){
  vector< map<string,string> > tcp_web = {
    {{"host", "199.16.156.6"}, {"port", "80"}}, //twitter
    {{"host", "199.16.156.230"}, {"port", "80"}},
    {{"host", "199.16.156.198"}, {"port", "80"}},
    {{"host", "199.16.156.38"}, {"port", "80"}},
    {{"host", "173.252.120.6"}, {"port", "80"}},//fb
    {{"host", "66.220.152.19"}, {"port", "80"}},
    {{"host", "74.125.136.136"}, {"port", "80"}}, //yt
    {{"host", "74.125.136.190"}, {"port", "80"}},
    {{"host", "74.125.136.91"}, {"port", "80"}},
    {{"host", "74.125.136.93"}, {"port", "80"}},
    {{"host", "66.211.160.86"}, {"port", "80"}}, //ebay
    {{"host", "66.135.216.190"}, {"port", "80"}},
    {{"host", "66.211.160.87"}, {"port", "80"}},
    {{"host", "173.194.65.138"}, {"port", "80"}}, //google
    {{"host", "173.194.65.101"}, {"port", "80"}},
    {{"host", "173.194.65.102"}, {"port", "80"}},
    {{"host", "173.194.65.113"}, {"port", "80"}},
    {{"host", "173.194.65.100"}, {"port", "80"}},
    {{"host", "173.194.65.139"}, {"port", "80"}},
    {{"host", "98.138.253.109"}, {"port", "80"}}, //yahoo
    {{"host", "206.190.36.45"}, {"port", "80"}},
    {{"host", "98.139.183.24"}, {"port", "80"}},
    {{"host", "123.125.114.144"}, {"port", "80"}}, //baidu
    {{"host", "220.181.57.216"}, {"port", "80"}},
    {{"host", "220.181.57.217"}, {"port", "80"}},
    {{"host", "205.251.242.54"}, {"port", "80"}}, //amazon
    {{"host", "176.32.98.166"}, {"port", "80"}},
    {{"host", "72.21.215.232"}, {"port", "80"}}};

  vector< map<string,string> > udp_web = {
    {{"host", "212.45.144.88"}, {"port", "123"}}, //pool.ntp.org
    {{"host", "5.9.80.114"}, {"port", "123"}},
    {{"host", "87.195.109.220"}, {"port", "123"}},
    {{"host", "212.43.246.10"}, {"port", "123"}},
    {{"host", "85.119.80.232"}, {"port", "123"}},
    {{"host", "91.198.10.4"}, {"port", "123"}},
    {{"host", "91.148.192.49"}, {"port", "123"}},
    {{"host", "37.187.56.220"}, {"port", "123"}},
    {{"host", "213.235.200.199"}, {"port", "123"}},
    {{"host", "129.250.35.250"}, {"port", "123"}},
    {{"host", "46.254.216.12"}, {"port", "123"}},
    {{"host", "129.70.132.37"}, {"port", "123"}},
    {{"host", "194.100.206.70"}, {"port", "123"}},
    {{"host", "178.62.250.107"}, {"port", "123"}},
    {{"host", "46.165.194.70"}, {"port", "123"}},
    {{"host", "91.207.136.50"}, {"port", "123"}}};

  vector< map<string,string> > tcp_local = {
    {{"host", iface_str}, {"port", std::to_string(local_tcp_echo_port)}} };
  vector< map<string,string> > udp_local = {
    {{"host", iface_str}, {"port", std::to_string(local_udp_echo_port)}} };


  test_requests[proc["PID"]]["perms"]   = perms;
  test_requests[proc["PID"]]["path"]    = proc["path"];
  vector< map<string,string> > tcptestsites;
  vector< map<string,string> > udptestsites;
  if (localtest){
    tcptestsites = tcp_web;
    udptestsites = udp_web;}
  else {
    tcptestsites = tcp_local;
    udptestsites = udp_local;}
  int randidx;
  if (proc["mode"] == "client"){
    if (proc["proto"] == "TCP"){
      randidx = rand() % tcptestsites.size();
      test_requests[proc["PID"]]["host"]       = tcptestsites[randidx]["host"];
      test_requests[proc["PID"]]["remoteport"] = tcptestsites[randidx]["port"];
    }
    else if (proc["proto"] == "UDP"){
      randidx = rand() % udptestsites.size();
      test_requests[proc["PID"]]["host"]       = udptestsites[randidx]["host"];
      test_requests[proc["PID"]]["remoteport"] = udptestsites[randidx]["port"];
    }
  }
  else if (proc["mode"] == "server"){
    test_requests[proc["PID"]]["host"]       = iface_str;
    test_requests[proc["PID"]]["remoteport"] = "0"; //TODO
  }
  test_requests[proc["PID"]]["localport"] = proc["localport"];
  test_requests[proc["PID"]]["starttime"] = proc["starttime"];
  proc["perms"] = perms;
  proc["host"] = test_requests[proc["PID"]]["host"];
  proc["remoteport"] = test_requests[proc["PID"]]["remoteport"];
}


string random_verdict(){
  vector<string> verdicts = {"ALLOW_ONCE", "ALLOW_ALWAYS", "DENY_ONCE", "DENY_ALWAYS"};
  return verdicts[rand() % verdicts.size()];
}


//Make sure all requests reach the frontend correctly formatted
void test1(vector<procmap> procs){
  int i;
  for (i=0; i < procs.size(); ++i){
    int rv = remove(string("/tmp/lpfwtest/awaiting_reply.false").c_str());
    if (rv == -1 && i != 0){
      fprintf(stderr, "remove errno is  %d - %s\n", errno, strerror(errno));
      exit(1);
    }
    if (procs[i]["mode"] == "client"){
      if (procs[i]["proto"] == "TCP"){
        issue_command(procs[i], "quicktcp " + procs[i]["host"] + " " + procs[i]["remoteport"]);}
      else if (procs[i]["proto"] == "UDP"){
        issue_command(procs[i], "quickudp " + procs[i]["host"] + " " + procs[i]["remoteport"]);}
    }
    if (procs[i]["mode"] == "server"){
      if (procs[i]["proto"] == "TCP"){
        issue_command(procs[i], "localtcpquicksend");}
      if (procs[i]["proto"] == "UDP"){
        issue_command(procs[i], "localudpquicksend");}
    }
    int ret = wait_for_semaphore_file("/tmp/lpfwtest/awaiting_reply.false", true);
    if (ret == false){
      cout << "Timeout waiting on the semaphore file /tmp/lpfwtest/awaiting_reply.false \n";
      cout << procs[i]["path"] << "\n";
      cout << "current seconds:" << current_seconds();
      abort();
      exit(1);
    }
    cout << "Semaphore released at:" << current_seconds() << "\n";
  }
  sleep(2); //allow connection to local servers to reach frontend

  if (test_requests.size() == 0){
    cout << "TEST 1 PASSED \n";
  }
  else {
    cout << "TEST 1 FAILED because size was " << test_requests.size() << "\n";
    exit(1);
  }
}


//Check that all processes were correctly added to rules
void test2(vector<procmap> procs){
  int i,j;
  _pthread_mutex_lock ( &rules_mutex );
  vector<rule> rulescopy = rules;
  _pthread_mutex_unlock ( &rules_mutex );
  cout << "rules size is:" << rulescopy.size() << "\n";
  bool bFound;
  for (i=0; i < procs.size(); ++i){
    bFound = false;
    for (j=0; j < rulescopy.size(); ++j){
      if (rulescopy[j].path == procs[i]["path"] &&
          rulescopy[j].pid == procs[i]["PID"] &&
          rulescopy[j].perms == procs[i]["perms"] &&
          rulescopy[j].is_active == true &&
          ((rulescopy[j].first_instance && procs[i]["firstinstance"] == "true") ||
          (!rulescopy[j].first_instance && procs[i]["firstinstance"] == "false"))&&
          std::to_string(rulescopy[j].stime) == procs[i]["starttime"]){
        rulescopy.erase(rulescopy.begin()+j);
        bFound = true;
        break;
      }
    }
    if (!bFound){
      cout << " TEST 2 FAILED \n";
      exit(1);
    }
  }
  cout << " TEST 2 PASSED \n";
}


//Check if processes can connect to the outside
void test3(vector<procmap> procs){
  int i;
  for (i=0; i < procs.size(); ++i){
    if (procs[i]["mode"] == "client"){
      if (procs[i]["proto"] == "TCP"){
        issue_command(procs[i], "tcp " + procs[i]["host"] + " " + procs[i]["remoteport"]
          + " " + procs[i]["perms"]);
      }
      else if  (procs[i]["proto"] == "UDP"){
        issue_command(procs[i], "udp " + procs[i]["host"] + " " + procs[i]["remoteport"]
          + " " + procs[i]["perms"]);
      }
    }
    if (procs[i]["mode"] == "server"){
      if (procs[i]["proto"] == "TCP"){
        issue_command(procs[i], "localtcpconnect");}
      if (procs[i]["proto"] == "UDP"){
        issue_command(procs[i], "localudpconnect");}
    }
    //if we dont sleep here, we can overwhelm the nfqueue which will cause tests to fail
    struct timespec refresh_timer,dummy;
    refresh_timer.tv_sec=0;
    refresh_timer.tv_nsec=1000000000/50;
    while(nanosleep(&refresh_timer, &refresh_timer));
  }
  //allow to establish connections and write all the .connected files
  for (int s=0;s<5;++s){
    cout << "Sleeping: " << s << "\n";
    sleep(1);
  }

  for (i=0; i < procs.size(); ++i){
    string randID = procs[i]["randID"];
    bool exists = fileExists("/tmp/lpfwtest/" + randID + ".connected");
    if ( (exists && procs[i]["perms"] == "ALLOW_ONCE") ||
         (exists && procs[i]["perms"] == "ALLOW_ALWAYS") ||
         (!exists && procs[i]["perms"] == "DENY_ALWAYS") ||
         (!exists && procs[i]["perms"] == "DENY_ONCE") ) {continue;}
    //else
    cout << " TEST 3 FAILED \n";
    cout << "randID: " << randID <<  " perms: " << procs[i]["perms"]
         << " host: " << procs[i]["host"] << " port " << procs[i]["localport"] << "\n";
    exit(1);
  }
  cout << " TEST 3 PASSED \n";
}


//Terminates all processes and check if rules correctly reflect that
//type is a type of processes that must be terminated:
//all, firstinstance, fork
void test4(vector<procmap> procs, string type = "all"){
  int i,j;
  vector<procmap> procs_terminated;
  vector<procmap> procs_still_running;
  for (i=0; i < procs.size(); ++i){
    if (type == "firstinstance"){
      if (procs[i]["firstinstance"] == "true") {
        procs_terminated.push_back(procs[i]);
        continue;
      }
      else {procs_still_running.push_back(procs[i]);}
    }
    else if (type == "all"){
      procs_terminated.push_back(procs[i]);
    }
    else if (type == "fork"){
      if (procs[i]["firstinstance"] != "true") {
        procs_terminated.push_back(procs[i]);
        continue;
      }
      else {procs_still_running.push_back(procs[i]);}
    }
  }

  for (i=0; i < procs_terminated.size(); ++i){
    issue_command(procs_terminated[i], "terminate");
  }
  sleep(2); //allow all rules to be deleted/marked inactive
  _pthread_mutex_lock ( &rules_mutex );
  vector<rule> rulescopy = rules;
  _pthread_mutex_unlock ( &rules_mutex );

  vector<procmap> procs_expected_in_rules;
  //check if correct procs are left in rules after termination
  for (i=0; i < procs.size(); ++i){
    if (type == "all"){
      if ( !(procs[i]["perms"] == "ALLOW_ALWAYS" || procs[i]["perms"] == "DENY_ALWAYS")) {continue;}
      if (procs[i]["firstinstance"] == "true"){
        procs_expected_in_rules.push_back(procs[i]);
      }
    }
    else if (type == "firstinstance"){
      if (procs[i]["firstinstance"] != "true"){
        procs_expected_in_rules.push_back(procs[i]);
      }
    }
    else if (type == "fork"){
      if (procs[i]["firstinstance"] == "true"){
        procs_expected_in_rules.push_back(procs[i]);
      }
    }
  }

  if (procs_expected_in_rules.size() != rulescopy.size()){
    cout << " TEST 4 FAILED (error 5) \n";
    exit(1);
  }
  for (i=0; i < procs_expected_in_rules.size(); ++i){
    procmap proc = procs_expected_in_rules[i];
    bool bFound = false;
    for (j=0; j < rulescopy.size(); ++j){
      if (rulescopy[j].path == proc["path"] ){
       bFound = true;
       if (type == "all" && (rulescopy[j].perms == "ALLOW_ONCE" || rulescopy[j].perms == "DENY_ONCE" ||
           rulescopy[j].is_active || rulescopy[j].pid != "0")) {
         cout << " TEST 4 FAILED (error 1) \n";
         exit(1);
       }
       rulescopy.erase(rulescopy.begin()+j);
       break;
      }
    }
    if (!bFound){
      cout << " TEST 4 FAILED (error 2)\n";
      exit(1);
    }
  }

  cout << " TEST 4 PASSED \n";
}




void start_local_echo_servers(){
  pthread_t thr_tcpserver;
  pthread_create(&thr_tcpserver ,(pthread_attr_t*)NULL, tcp_server, (void *)NULL);
  pthread_t thr_udpserver;
  pthread_create(&thr_udpserver ,(pthread_attr_t*)NULL, udp_server, (void *)NULL);
}



//Local TCP echo server which accepts connections and immediately closes them
void *tcp_server (void *ptr){
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
      die("testprocess: inet_pton() failed"); }

  servaddr.sin_port = htons(0);
  if ( bind(list_s, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 ) {
     fprintf(stderr, "ECHOSERV: Error calling bind()\n");
     fprintf(stderr, "The errno is  %d - %s\n", errno, strerror(errno));
  }
  struct sockaddr_in sin;
  socklen_t addrlen = sizeof(sin);
  if(getsockname(list_s, (struct sockaddr *)&sin, &addrlen) == 0 &&
    sin.sin_family == AF_INET && addrlen == sizeof(sin)) {
    local_tcp_echo_port = ntohs(sin.sin_port);
  }

  if ( listen(list_s, 500) < 0 ) {
    fprintf(stderr, "ECHOSERV: Error calling listen()\n");
    exit(EXIT_FAILURE);
  }
  cout << "Local TCP echoserver is listening on port " <<  local_tcp_echo_port << "\n";

  int connfd;
  int i = 0;
  while (true){
    connfd = accept(list_s, NULL, NULL);
    i++;
    //cout << "****************TCP ECHO SERVER got conn no " << i << "\n";
    if ( connfd < 0 ) {
          fprintf(stderr, "ECHOSERV: Error calling accept()\n");
          exit(EXIT_FAILURE);
    }
    close(connfd);
  }
}


//Local UDP echo server which sends data in response
void *udp_server (void *ptr){
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
      die("testprocess: inet_pton() failed"); }

  servaddr.sin_port        = htons(0);
  if ( bind(list_s, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 ) {
     fprintf(stderr, "ECHOSERV: Error calling bind()\n");
     abort();
  }
  struct sockaddr_in sin;
  socklen_t addrlen = sizeof(sin);
  if(getsockname(list_s, (struct sockaddr *)&sin, &addrlen) == 0 &&
    sin.sin_family == AF_INET && addrlen == sizeof(sin)) {
    local_udp_echo_port = ntohs(sin.sin_port);
  }

  char msg[1] = {1};
  char buf[1000];
  int i = 0;
  struct sockaddr_in clientaddr; /* client addr */
  socklen_t clientlen; /* byte size of client's address */
  clientlen = sizeof(clientaddr);

  while (true){
    recvfrom(list_s, buf, 1000, 0, (struct sockaddr *) &clientaddr, &clientlen); //block until data
    i++;
    //cout << "****************UDP ECHO SERVER got conn no " << i << "\n";
    int n = sendto(list_s, msg, sizeof(msg), 0, (struct sockaddr *) &clientaddr, clientlen);
    if (n < 0){
      fprintf(stderr, "Error in send() %d - %s\n", errno, strerror(errno));
    }
  }
}


//Makes sure te fork was started an adds a parentproc's fork to proc list
procmap new_forked_proc(procmap parentproc){
  string child_randID = parentproc["randID"]+".fork";
  wait_for_semaphore_file("/tmp/lpfwtest/"+child_randID+".pid-file-is-ready");
  string pid_str;
  ifstream pidfile("/tmp/lpfwtest/"+child_randID+".pid");
  getline(pidfile, pid_str);
  pidfile.close();
  assert (pid_str != "");
  procmap childproc;
  childproc["randID"] = child_randID;
  childproc["PID"] = pid_str;
  childproc["path"] = parentproc["path"];
  childproc["proto"] = parentproc["proto"];
  childproc["mode"] = parentproc["mode"];
  childproc["perms"] = parentproc["perms"];
  childproc["host"] = parentproc["host"];
  childproc["remoteport"] = parentproc["remoteport"];
  issue_command(childproc, "client");
  if (childproc["mode"] == "client"){
    if ( childproc["proto"] == "TCP"){
      issue_command(childproc, "bind_tcp_client");}
    else if ( childproc["proto"] == "UDP"){
      issue_command(childproc, "bind_udp_client");}
  }
  else if (childproc["mode"] == "server"){
    if (childproc["proto"] == "TCP"){
      issue_command(childproc, "localtcpserver");}
    else if (childproc["proto"] == "UDP"){
      issue_command(childproc, "localudpserver");}
  }
  childproc["starttime"] = starttimeGet(childproc);
  childproc["localport"] = get_port_number(childproc);
  childproc["firstinstance"] = "false";
  return childproc;
}


void* thread_test ( void *data ) {
  //clean up the dir from previous test run
  system("rm -R /tmp/lpfwtest");
  system("mkdir /tmp/lpfwtest");
  ifstream ifacefile("/tmp/lpfwtestinterface");
  if (! ifacefile.is_open()) {
      cout << "Could not find /tmp/lpfwtestinterface file\n";
      cout << "This file should contain your network interface IP, e.g. 109.110.9.42\n";
      cout << "I cannot use the loopback interface to send outgoing packets\n";
      cout << "That's why I need any other of your interfaces\n";
      exit(1);
  }
  getline(ifacefile, iface_str);
  ifacefile.close();
  assert (iface_str != "");
  pthread_t thr_frontend;
  _pthread_create(&thr_frontend ,(pthread_attr_t*)NULL, frontend_thread, (void *)NULL);

  wait_for_semaphore_file("/tmp/lpfwtest/frontend-is-ready");
  int i,j;
  //pay attention to dmesg output - NFQUEUE can't queue up more than 200 packets
  //it will drop the overflow and tests will fail. Dont create too many simultaneous conns.
  //you may want to increase sleep time between connections in test3
  int newprocs = 10;
  start_local_echo_servers();

  vector<procmap> procs =  new_processes(newprocs, "client", "TCP");
  vector<procmap> procs2 = new_processes(newprocs, "client", "UDP");
  vector<procmap> procs3 = new_processes(newprocs, "server", "TCP");
  vector<procmap> procs4 = new_processes(newprocs, "server", "UDP");
  procs.insert( procs.end(), procs2.begin(), procs2.end() );
  procs.insert( procs.end(), procs3.begin(), procs3.end() );
  procs.insert( procs.end(), procs4.begin(), procs4.end() );
  std::random_shuffle ( procs.begin(), procs.end() );
  for (i=0;i<procs.size();++i){
    expect_request(procs[i], random_verdict());
  }

  //if you use this, you must comment out test1 and test2
  for (int i=0;i<procs.size();++i){
    expect_request(procs[i], random_verdict());
    unsigned long long stime = stoll(procs[i]["starttime"]);
    ruleslist_add(procs[i]["path"], procs[i]["PID"], procs[i]["perms"], true, "", stime, 0, true);
  }

  //fork and connect
  vector<procmap> forked_procs;
  for (i=0;i<procs.size();++i){
    issue_command(procs[i], "fork");
    procmap childproc = new_forked_proc(procs[i]);
    if (childproc["mode"] == "client"){
      if (childproc["proto"] == "TCP"){
        issue_command(childproc, "quicktcp " + childproc["host"] + " " + childproc["remoteport"]);}
      else if (childproc["proto"] == "UDP"){
        issue_command(childproc, "quickudp " + childproc["host"] + " " + childproc["remoteport"]);}
    }
    else if (childproc["mode"] == "server"){
      if (childproc["proto"] == "TCP"){
        issue_command(childproc, "localtcpquicksend");}
      if (childproc["proto"] == "UDP"){
        issue_command(childproc, "localudpquicksend");}
    }
    forked_procs.push_back(childproc);
  }
  procs.insert( procs.end(), forked_procs.begin(), forked_procs.end() );
  std::random_shuffle ( procs.begin(), procs.end() );

  //test1(procs);
  //sleep(2); //allow the last rule to be added
  //test2(procs);
  test3(procs);
  //pick on of the possible test4's
  test4(procs, "all");
  //test4(procs, "firstinstance");
  //test4(procs, "fork");
  sleep(50);

  exit(0);
}
