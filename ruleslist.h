#ifndef RULESLIST_H
#define RULESLIST_H

#include "common/includes.h" //for struct rule
#include "common/syscall_wrappers.h"
#include <vector>
#include <string>

using namespace std;

//return values for all member functions
//not all fields are used by each function
struct ruleslist_rv{
  bool success;
  uint32_t ctmark;
  vector<uint32_t> ctmarks_to_delete;
  string errormsg;
};


//conntrack marks
struct ctmarks{
  uint32_t in;
  uint32_t out;
};




class RulesList
{
public:
  RulesList(vector<rule> newrules);
  ruleslist_rv add ( const string path, const string pid, const string perms,
                       const bool active, const string sha, const unsigned long long stime,
                       const int ctmark, const bool first_instance);
  ruleslist_rv remove ( const string path,  const string perms, const string pid);
  vector<rule> get_rules_copy();
  ruleslist_rv mark_inactive(string path, string pid);
  ruleslist_rv mark_active(string path, string newpid, unsigned long long newstime);

private:
  ctmarks get_ctmarks();
  string get_sha256_hexdigest(string exe_path);
  vector<rule> rules;
  pthread_mutex_t rules_mutex;
  u_int32_t ctmark_count;
  pthread_mutex_t ctmark_mutex;
  string path_to_proc = "/proc/"; //can be changed for unittesting
};

#endif // RULESLIST_H
