#include "ruleslist.h"
#include <assert.h>
#include "sha256/sha256.h"

string get_uid() {
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


RulesList::RulesList(vector<rule> newrules)
{
  rules_mutex = PTHREAD_MUTEX_INITIALIZER;
  ctmark_count = 0;
  ctmark_mutex = PTHREAD_MUTEX_INITIALIZER;
  //give each rule a ctmark if needed and a uid
  for (int i=0; i < newrules.size(); i++){
    if (! newrules[i].is_fixed_ctmark){
      ctmarks c = get_ctmarks();
      newrules[i].ctmark_out = c.out;
      newrules[i].ctmark_in = c.in;
    }
    newrules[i].uid = get_uid();
  }
  rules = newrules;
}

ruleslist_rv RulesList::add ( const string path, const string pid, const string perms,
                     const bool active, const string sha, const unsigned long long stime,
                     const int ctmark, const bool first_instance){
  ruleslist_rv rv;

  rule newrule;
  newrule.path = path;
  newrule.pid = pid;
  newrule.perms = perms;
  newrule.is_active = active;
  newrule.stime = stime;
  newrule.uid = get_uid();
  //rules added by frontend dont have their sha
  if (sha == "") {
    string retval = get_sha256_hexdigest(path);
    if (retval == "CANT_READ_EXE") {
      rv.success = false;
      rv.errormsg = "CANT_READ_EXE";
      return rv;
    }
    else{
      newrule.sha = retval;
    }
  }
  else { newrule.sha = sha; }
  if (ctmark == 0) {
    ctmarks c = get_ctmarks();
    newrule.ctmark_in = c.in;
    newrule.ctmark_out = c.out;
  }
  else { // ctmark > 0 => assign parent's ctmark
    //either ctmark is for in or out traffic
    if (ctmark >= CTMARKIN_BASE){
      newrule.ctmark_in = ctmark;
      newrule.ctmark_out = ctmark - CTMARK_DELTA;
    }
    else {
      newrule.ctmark_out = ctmark;
      newrule.ctmark_in = ctmark + CTMARK_DELTA;
    }
  }
  newrule.first_instance = first_instance;

  _pthread_mutex_lock ( &rules_mutex );

  //make sure it's not a duplicate rule
  for(int i=0; i < rules.size(); i++){
    if (rules[i].path == path && rules[i].pid == pid){
      cout << "path " << path << " pid " << pid;
      _pthread_mutex_unlock ( &rules_mutex );
      rv.success = false;
      rv.errormsg = "Duplicate rules not allowed";
      return rv;
    }
  }
  if (newrule.is_active){
    newrule.pidfdpath = path_to_proc + newrule.pid + "/fd/";
    newrule.dirstream = _opendir (newrule.pidfdpath.c_str());
    try {
      newrule.dirstream = _opendir (newrule.pidfdpath.c_str());
    } catch(...) {
      if (perms == ALLOW_ONCE || perms == DENY_ONCE){
        _pthread_mutex_unlock ( &rules_mutex );
        rv.success = false;
        rv.errormsg = "Rule with perms ONCE terminated";
        return rv;
      }
      else {
        //we still want to add the rule even though the process terminated
        newrule.dirstream = NULL;
      }
    }
  }

  rules.push_back(newrule);
  _pthread_mutex_unlock ( &rules_mutex );
  rv.ctmark = newrule.ctmark_out;
  rv.success = true;
  return rv;
}

//As a sanity check the caller must pass perms (although we could figure out the perms ourselves)

ruleslist_rv RulesList::remove (const string path, const string perms, const string pid = "all") {

  bool bRulesChanged = false;
  ruleslist_rv rv;
  vector<u_int32_t> ctmarks;

  _pthread_mutex_lock ( &rules_mutex );

  for(int i=0; i < rules.size(); i++){
    if (rules[i].path != path) continue;
    if (pid != "all" && rules[i].pid != pid ) continue;
    if (rules[i].perms != perms){
      _pthread_mutex_unlock ( &rules_mutex );
      rv.success = false;
      rv.errormsg = "Caller passed incorrect permission";
      return rv;
    }
    if (rules[i].is_active) {
      try {
      _closedir (rules[i].dirstream);
      } catch(...) {
        //noop: the process terminated abruptly
      }
      ctmarks.push_back(rules[i].ctmark_in);
      ctmarks.push_back(rules[i].ctmark_out);
    }

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
    rv.ctmarks_to_delete = ctmarks;
    return rv;
  }
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

//called by thread_refresh when an ALWAYS process terminates
ruleslist_rv RulesList::mark_inactive(string path, string pid){
  bool bRuleFound = false;
  ruleslist_rv rv;

  _pthread_mutex_lock ( &ctmark_mutex );
  for(int i=0; i < rules.size(); i++){
    if (rules[i].path != path) continue;
    if (rules[i].pid != pid ) continue;
    bRuleFound = true;
    rules[i].pid = "0";
    rules[i].is_active = false;
    //conntrack marks will be used by the next instance of app
    ctmarks c = get_ctmarks();
    rules[i].ctmark_in = c.in;
    rules[i].ctmark_out = c.out;
    break;
  }
  _pthread_mutex_unlock ( &ctmark_mutex );

  if (!bRuleFound){
    rv.success = false;
    rv.errormsg = "Failed to find rule to mark as inactive";
    return rv;
  }
  else{
    rv.success = true;
    return rv;
  }
}


//NOTE the assumption is broken
//The assumption here is that only one inactive rule for a given path may be present
//Because ONCE rules when they become inactive are removed from rules
//
//HOWEVER!!! what if an ALWAYS proc is inactive and another instance of it is
//started. You will have 2 inactive rules!!!
ruleslist_rv RulesList::mark_active(string path, string newpid, unsigned long long newstime){
  _pthread_mutex_lock ( &ctmark_mutex );
  bool bRuleFound = false;
  ruleslist_rv rv;
  u_int32_t ctmark;

  for(int i=0; i < rules.size(); i++){
    if (rules[i].path != path) continue;
    bRuleFound = true;
    assert(! rules[i].is_active);
    string pidfdpath = path_to_proc + newpid + "/fd/";
    DIR *dirstream = opendir(pidfdpath.c_str());
    if (dirstream == NULL) {
      _pthread_mutex_unlock ( &ctmark_mutex );
      rv.success = false;
      rv.errormsg = "Process terminated abruptly when marking it as active";
      return rv;
    }
    rules[i].pid = newpid;
    rules[i].is_active = true;
    rules[i].stime = newstime;
    rules[i].pidfdpath = pidfdpath;
    if (! rules[i].is_fixed_ctmark){
      ctmarks c = get_ctmarks();
      rules[i].ctmark_in = c.in;
      rules[i].ctmark_out = c.out;
    }
    ctmark = rules[i].ctmark_out;
  }
  _pthread_mutex_unlock ( &ctmark_mutex );
  if (!bRuleFound){
    rv.success = false;
    rv.errormsg = "Failed to find rule while marking active";
    return rv;
  }
  else {
    rv.success = true;
    rv.ctmark = ctmark;
    return rv;
  }
}

string RulesList::get_sha256_hexdigest(string exe_path){
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
