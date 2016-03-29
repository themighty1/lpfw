#include "removeterminated.h"
#include <assert.h>
#include <unistd.h> //for sleep()
#include <string.h> //for memset()

RemoveTerminated::RemoveTerminated(RulesList* rl)
{
    rulesList = rl;
}


void RemoveTerminated::loop(){
    while(true){
      iteration();
      sleep (refresh_interval);
    }
}


void RemoveTerminated::iteration(){
  char exe_path[PATHSIZE] = {0};

  vector<rule> rules = rulesList->get_rules_copy();
  for(int i=0; i < rules.size(); i++){
     //only interested in active processes
     if (rules[i].is_permanent) continue;
     string proc_pid_exe = "/proc/" + rules[i].pid + "/exe";
     memset ( exe_path, 0, PATHSIZE );
     //readlink doesn't fail if PID is running
     if ( readlink ( proc_pid_exe.c_str(), exe_path, PATHSIZE ) != -1 ) continue;
     //else the PID is not running anymore
     rulesList->removeInactive(rules[i].path, rules[i].perms, rules[i].pid );
  }
}
