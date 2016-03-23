#ifndef RULESLIST_H
#define RULESLIST_H

#include "common/includes.h" //for struct rule
#include <vector>
#include <string>

using namespace std;

//conntrack marks
struct ctmarks{
  uint32_t in;
  uint32_t out;
};

//return values for all member functions
//not all fields are used by each function
struct ruleslist_rv{
  bool success = false;
  uint32_t ctmark;
  vector<ctmarks> ctmarks_to_delete;
  string errormsg = "Error";
  int value = -1;
};



class RulesList
{
friend class RulesListFriend;

public:
  RulesList(vector<rule> newrules);
  ruleslist_rv pathFindAndAdd (const string path_in,
                               const string pid_in, const unsigned long long stime_in);
  ruleslist_rv addFromUser ( const string path, const string pid,
                                        const string perms, const unsigned long long stime);
  ruleslist_rv removeInactive (const string path, const string perms, const string pid);
  ruleslist_rv removePermanent (const string path, const string perms);
  vector<rule> get_rules_copy();

private:
  ruleslist_rv addNewInstance ( const string path, const string pid, const string parent_perms,
                                        const string parent_sha, const int parent_ctmark);
  void addForked ( const string path, const string pid, const string parentpid,
                                        const string perms, const string sha, const int ctmark);
  ctmarks get_ctmarks();
  string get_sha256_hexdigest(string exe_path);
  unsigned long long get_starttime ( string pid );
  string get_uid();
  string get_parent_pid(string child_pid);
  vector<rule> rules;
  pthread_mutex_t rules_mutex;
  //todo ctmark_* vars can be made static inside RulesList::get_ctmarks()
  u_int32_t ctmark_count;
  pthread_mutex_t ctmark_mutex;
  string path_to_proc = "/proc/"; //unittests change this to from /proc/ to /tmp/
  void _pthread_mutex_lock(pthread_mutex_t*);
  void _pthread_mutex_unlock(pthread_mutex_t*);
  DIR *_opendir(string path);
  string _readlink(string path);
  void push(rule newrule);
};

#endif // RULESLIST_H
