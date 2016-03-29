#include <assert.h>
#include <exception>
#include <iostream> //for cout()
#include <string.h> //for memset
#include "ruleslist.h"
#include "sha256/sha256.h"


RulesList::RulesList(vector<rule> newrules){
  rules_mutex = PTHREAD_MUTEX_INITIALIZER;
  ctmark_count = 0;
  ctmark_mutex = PTHREAD_MUTEX_INITIALIZER;

  //give each rule a ctmark
  for (int i=0; i < newrules.size(); i++){
    if (! newrules[i].is_fixed_ctmark){
      ctmarks c = get_ctmarks();
      newrules[i].ctmark_out = c.out;
      newrules[i].ctmark_in = c.in;
    }
    newrules[i].is_permanent = true;
  }
  rules = newrules;
}



//This function may be called on 3 occasions:
//2. socket_active_processes_search() didnt find the process because
///proc/<PID>/fd socket entry wasn't yet created
//3. (most usual case) A process associated with socket was found and now we need to check
//if another rule with the same path is in rules. If so, we are either a fork()ed child or a new instance



//returns success when function terminates properly
//if an exception happens, return an error
ruleslist_rv RulesList::pathFindAndAdd (const string path,
                             const string pid, const unsigned long long stime){
  //TODO what do we use stime for?
  assert(pid != "0");
  ruleslist_rv rv;

  try{
  rv.success = false;
  vector<rule> rulescopy = get_rules_copy();
  vector<rule> rulesWithTheSamePath;
  int i;
  for(i = 0; i < rulescopy.size(); ++i) {
    if (rulescopy[i].path != path) continue;
    if (rulescopy[i].pid == pid){
    //socket_active_processes_search() didnt pick it up, try again
    rv.success = true;
    rv.value = SEARCH_ACTIVE_PROCESSES_AGAIN;
    return rv;
    }
    rulesWithTheSamePath.push_back(rulescopy[i]);
  }
  if (!rulesWithTheSamePath.size()) {
    rv.success = true;
    rv.value = PATH_IN_RULES_NOT_FOUND;
    return rv;
  }

  string ppid = get_parent_pid(pid);
  cout << "the parent pid was:" << ppid << endl;
  //If parent's PID is present in rules, then we are dealing with a fork()
  for(i = 0; i < rulesWithTheSamePath.size(); i++) {
    //there can only be a fork() of a current process
    if (rulesWithTheSamePath[i].is_permanent) continue;
    if (rulesWithTheSamePath[i].pid != ppid) continue;
    rule parent_rule = rulesWithTheSamePath[i];
    if (parent_rule.is_forked){
      //We dont allow a fork() of a fork() as it would create a bookkeeping mess
      //So, to keep it simple we treat this process as a new instance
      break;
    }

    addForked(path, pid, ppid, parent_rule.perms, parent_rule.sha, parent_rule.ctmark_out);

    if (parent_rule.perms == ALLOW_ALWAYS || parent_rule.perms == ALLOW_ONCE){
      rv.value = FORKED_CHILD_ALLOW;}
    else if (parent_rule.perms == DENY_ALWAYS || parent_rule.perms == DENY_ONCE){
      rv.value = FORKED_CHILD_DENY;}

    rv.success = true;
    rv.ctmark = parent_rule.ctmark_out;
    //TODO: how to get in touch with frontend?
    //if (bFrontendActive) {send_rules();}
    return rv;
  }

  //We are dealing with a new instance. Is is_permanent rule present for this path?
  for(i = 0; i < rulesWithTheSamePath.size(); i++) {
    if (!rulesWithTheSamePath[i].is_permanent) continue;
    rule parent = rulesWithTheSamePath[i];
    ruleslist_rv rvANI;
    rvANI = addNewInstance(path, pid, parent.perms, parent.sha, parent.ctmark_out);

    if (parent.perms == ALLOW_ALWAYS){
      rv.value = NEW_INSTANCE_ALLOW;}
    else if (parent.perms == DENY_ALWAYS){
      rv.value = NEW_INSTANCE_DENY;}
    else{
        assert(true); //is_permanent must only have *ALWAYS permission
    }

    rv.success = true;
    rv.ctmark = rvANI.ctmark;
    return rv;
  }

  //if new instance and existing rule is not is_permanent, query the user
  rv.success = true;
  rv.value = PATH_IN_RULES_FOUND_BUT_PERMS_ARE_ONCE;
  return rv;
  }
  catch(const string &e){
    //TODO cout << the exception error text
    rv.success = false;
    rv.errormsg = e;
    rv.value = GENERAL_ERROR;
    return rv;
  }
}



ruleslist_rv RulesList::addNewInstance ( const string path, const string pid, const string parent_perms,
                                      const string parent_sha, const int parent_ctmark){

  assert(parent_perms == ALLOW_ALWAYS || parent_perms == DENY_ALWAYS);
  ruleslist_rv rv;
  rv.success = false;
  rule newrule;
  //sha256 hasnt changed?
  string sha = get_sha256_hexdigest(path);
  if (sha != parent_sha) {
     throw string("SHA_DONT_MATCH in addNewInstance");
  }
  newrule.path = path;
  newrule.pid = pid;
  newrule.perms = parent_perms;
  newrule.sha = sha;
  if (parent_ctmark > CTMARK_DELTA){
    //ideally we want a predictable ctmark for rules with is_fixed_ctmark
    //for now, to keep it simple, the user is responsible for not running two instances
    //of the same rule with is_fixed_ctmark. They will both get the same ctmark and that
    //will mess up byte accounting
    newrule.ctmark_out = parent_ctmark;
    newrule.ctmark_in = parent_ctmark + CTMARK_DELTA;
  }
  else {
    ctmarks c = get_ctmarks();
    newrule.ctmark_out = c.out;
    newrule.ctmark_in = c.in;
  }
  newrule.stime = get_starttime(pid);
  newrule.uid = get_uid();
  newrule.pidfdpath = path_to_proc + pid + "/fd";
  newrule.dirstream = _opendir(newrule.pidfdpath);
  push(newrule);

  rv.ctmark = newrule.ctmark_out;
  return rv;
}


//add a process which was fork()ed from another process which was already in the ruleslist
//Note: the forked process' traffic is counted towards the parent's traffic
//Note: the forked process is not shown to the user
//Note: if the parent process terminates then despite the fact that the fork()ed process
//may still be running, the parent process with all its fork()ed processes
//will be removed from ruleslist
//and upon further traffic, the fork()ed process will be added to the rules list
//as a normal (not is_forked) rule
void RulesList::addForked ( const string path, const string pid, const string parentpid,
                                      const string perms, const string sha, const int ctmark){
  rule newrule;
  newrule.path = path;
  newrule.pid = pid;
  newrule.parentpid = parentpid;
  newrule.perms = perms;
  newrule.sha = sha;
  newrule.stime = get_starttime(pid);
  newrule.ctmark_out = ctmark;
  newrule.ctmark_in = ctmark + CTMARK_DELTA;
  newrule.is_forked = true;
  newrule.pidfdpath = path_to_proc + pid + "/fd";
  newrule.uid = get_uid();
  newrule.dirstream = _opendir (newrule.pidfdpath.c_str());
  push(newrule);
  //nothing to return because the caller already knows the passed-in ctmark
}


//user assigns a verdict

//Attack 1: when a legitimate process wants to connect and the request is sent to GUI,
//the attacker kills the process
//removes the exe from disk, puts a malicious exe in its place and starts the malicious process
//with the same PID.
//Mitigation (if the process being added is still active)
//check that stime of the initial process matches
//Mitigation (if the process terminated):
//Get sha256(path) before we send request to user
//and check that sha256 is the same before adding the *always rule to rulesfile

//TODO we dont do that for now to avoid complexity, instead we just dont add the rule
//if it terminated while the user was respondng.
//e.g. "host" sends a request and quickly terminates
//In this case the user will keep getting the prompt unless he can respond to the prompt quickly
//before "host" terminates

ruleslist_rv RulesList::addFromUser ( const string path, const string pid,
                                      const string perms, const unsigned long long stime){
  assert(pid != "0");
  assert(stime > 0);
  rule newrule;
  ruleslist_rv rv;

  try{
  string sha = get_sha256_hexdigest(path);
  newrule.sha = sha;

  //make sure that there is no (deleted) suffix in the path name
  cout << "will readlink " << (path_to_proc + pid + "/exe") << endl;
  string readlink_path = _readlink(path_to_proc + pid + "/exe");
  if ( readlink_path != path){
    rv.success = false;
    rv.errormsg = "/proc/PID/exe points to an unexpected path";
    return rv;
  }

  //check that stime is still the same
  if (get_starttime(pid) != stime){
    rv.success = false;
    rv.errormsg = "Starttime change detected";
    return rv;
  }

  //assign conntrack marks
  ctmarks c = get_ctmarks();
  newrule.ctmark_in = c.in;
  newrule.ctmark_out = c.out;

  //create an empty rule for the new *always rule
  if (perms == ALLOW_ALWAYS || perms == DENY_ALWAYS){
    rule permanent_rule;
    permanent_rule.path = path;
    permanent_rule.perms = perms;
    permanent_rule.sha = sha;
    permanent_rule.is_permanent = true;
    push(permanent_rule);
  }

  //both *always and *once rules are added normally
  newrule.path = path;
  newrule.pid = pid;
  newrule.perms = perms;
  newrule.stime = stime;
  newrule.uid = get_uid();
  //sha and ctmarks were added earlier
  newrule.pidfdpath = path_to_proc + newrule.pid + "/fd/";
  newrule.dirstream = _opendir (newrule.pidfdpath);
  push(newrule);

  rv.success = true;
  }catch(const string &e){
    rv.success = false;
    rv.errormsg = e;
  }
  return rv;
}


//As a sanity check the caller must pass perms (although we could figure out the perms ourselves)
//Remove a process which is no longer running. Also remove all fork()ed process for which this
//process is a parent
ruleslist_rv RulesList::removeInactive (const string path, const string perms, const string pid) {

  bool bRulesChanged = false;
  ruleslist_rv rv;
  vector<ctmarks> vctm;

  _pthread_mutex_lock ( &rules_mutex );

  for(int i=0; i < rules.size(); i++){
    //permanent rules always stay even when no processes are running
    if (rules[i].is_permanent) continue;
    if (rules[i].path != path) continue;
    if (! (rules[i].pid == pid || rules[i].parentpid == pid)) continue;
    if (rules[i].perms != perms){
      _pthread_mutex_unlock ( &rules_mutex );
      rv.success = false;
      rv.errormsg = "Caller passed incorrect permission";
      return rv;
    }
    //doesnt matter if closedir returns an error
    closedir (rules[i].dirstream);
    ctmarks c;
    c.in = rules[i].ctmark_in;
    c.out = rules[i].ctmark_out;
    vctm.push_back(c);

    rules.erase(rules.begin()+i);
    --i; //revisit the same index again
    bRulesChanged = true;
  }
  _pthread_mutex_unlock ( &rules_mutex );

  if (! bRulesChanged){
    rv.success = false;
    rv.errormsg = "Failed to find the rule";
    return rv;
  }
  else {
    rv.success = true;
    rv.ctmarks_to_delete = vctm;
    return rv;
  }
}


//remove rule from the permanent list
//also remove all processes and their children from the active list
//The GUI calls this function so there is no chance of a race condition with addFromUser
//because until this function exits no other requests from user will be processed
ruleslist_rv RulesList::removePermanent (const string path, const string perms) {
  _pthread_mutex_lock ( &rules_mutex );
  bool bPermanentFound = false;
  ruleslist_rv rv;
  rv.success = false;
  vector<ctmarks> vctm; //for those rules which are active

  for (int i=0; i < rules.size(); i++){
    if (! rules[i].is_permanent) continue;
    if (rules[i].path != path) continue;
    if (rules[i].perms != perms){
      _pthread_mutex_unlock ( &rules_mutex );
      rv.errormsg = "Wrong permission passed to removePermanent";
      return rv;
    }
    rules.erase(rules.begin()+i);
    bPermanentFound = true;
    break;
  }
  if (! bPermanentFound){
    _pthread_mutex_unlock ( &rules_mutex );
    rv.errormsg = "Could not find a rule among is_permanent";
    return rv;
  }
  _pthread_mutex_unlock ( &rules_mutex );

  vector<rule> rulescopy = get_rules_copy();
  //also remove all current rules with this path
  //loop through all PIDs (non-forked because forked ones will be removed anyway) with path/perms
  //and removeInactive one by one
  for (int i=0; i < rulescopy.size(); i++){
    if (rulescopy[i].path != path) continue;
    if (rulescopy[i].is_forked == true) continue;
    assert(rulescopy[i].pid != "0");
    ruleslist_rv rvRI = removeInactive(path, perms, rulescopy[i].pid);
    if (rvRI.success == false){
        cout << "error" << rvRI.errormsg << " in removePermanent while in removeInactive";
        assert(false);
    }
    //append vector
    vctm.insert(vctm.end(), rv.ctmarks_to_delete.begin(), rv.ctmarks_to_delete.end());
  }
  rv.success = true;
  rv.ctmarks_to_delete = vctm;
  return rv;
}


vector<rule> RulesList::get_rules_copy(){
  _pthread_mutex_lock ( &rules_mutex );
  vector<rule> rulescopy = rules;
  _pthread_mutex_unlock ( &rules_mutex );
  return rulescopy;
}


//return 2 conntrack marks: input and output
ctmarks RulesList::get_ctmarks(){
  _pthread_mutex_lock ( &ctmark_mutex );
  ++ctmark_count;
  ctmarks c;
  c.in = CTMARKIN_BASE + ctmark_count;
  c.out = CTMARKOUT_BASE + ctmark_count;
  _pthread_mutex_unlock ( &ctmark_mutex );
  return c;
}


string RulesList::get_sha256_hexdigest(string exe_path){
  const int _DIGEST_SIZE = 32;
  unsigned char sha_bytearray[_DIGEST_SIZE];
  memset(sha_bytearray, 0, _DIGEST_SIZE);
  FILE *stream = fopen(exe_path.c_str(), "r");
  if (!stream) {
    throw string("fopen error in get_sha256_hexdigest");
  }
  sha256_stream(stream, (void *)sha_bytearray);
  fclose(stream);
  //convert binary sha to hexlified string
  char sha_cstring [_DIGEST_SIZE*2+1];
  sha_cstring[_DIGEST_SIZE*2] = 0;
  for(int j = 0; j < _DIGEST_SIZE; j++)
  sprintf(&sha_cstring[2*j], "%02X", sha_bytearray[j]);
  return sha_cstring;
}


unsigned long long RulesList::get_starttime ( string pid ) {
  unsigned long long starttime;
  FILE *stream;
  string path = path_to_proc + pid + "/stat";
  stream = fopen (path.c_str(), "r" );
  if (stream == NULL) {
    throw string("stream == NULL in get_starttime");
  }
  fscanf ( stream, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s"
           "%*s %*s %*s %*s %*s %*s %*s %llu", &starttime );
  fclose ( stream );
  return starttime;
}


string RulesList::get_uid() {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    char s[13];

    for (int i = 0; i < 12; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[12] = 0;
    return string(s);
}

string RulesList::get_parent_pid(string child_pid){
  //Find this process's parent process' PID
  string proc_stat_path = "/proc/" + child_pid + "/stat";
  FILE *stream1 = fopen ( proc_stat_path.c_str(), "r" );
  if ( stream1 == NULL ) {
    throw string("PROCFS_ERROR in get_parent_pid");
  }
  char ppid[16];
  fscanf ( stream1, "%*s %*s %*s %s", ppid );
  fclose ( stream1);
  return string(ppid);
}


void RulesList::_pthread_mutex_lock(pthread_mutex_t* mutex){
  int retval = pthread_mutex_lock(mutex);
  assert(retval == 0);
}

void RulesList::_pthread_mutex_unlock(pthread_mutex_t* mutex){
  int retval = pthread_mutex_unlock(mutex);
  assert(retval == 0);
}

DIR* RulesList::_opendir(string path){
  DIR* o = opendir(path.c_str());
  if (o == NULL){throw string("_opendir error");}
  return o;
}


string RulesList::_readlink(string path){
  char path_out[PATHSIZE] = {0};
  int rv = readlink (path.c_str(), path_out, PATHSIZE );
  if (rv == -1){
    throw string("_readlink() error");
  }
  return string(path_out);
}


void RulesList::push(rule newrule){
  //check if this is not a duplicate and then push
  _pthread_mutex_lock ( &rules_mutex );
  for(int i=0; i < rules.size(); i++){
    if (rules[i].path == newrule.path && rules[i].pid == newrule.pid){
        cout << "Duplicate: path " << newrule.path << " pid "
             << newrule.pid << endl;
        _pthread_mutex_unlock ( &rules_mutex );
        throw string("Cannot push duplicate rule");
    }
  }
  rules.push_back(newrule);
  _pthread_mutex_unlock ( &rules_mutex );
}
