#include "gtest/gtest.h"
#include "ruleslist.h"
#include "unix_socket.h"
#include <fstream>
#include <signal.h> //for kill()
#include <stdio.h>
#include <unistd.h> //for symlink()

//creates dirs recursively up until the last dir in the path
static void _mkdir(const char *dir) {
        char tmp[256];
        char *p = NULL;
        size_t len;

        snprintf(tmp, sizeof(tmp),"%s",dir);
        len = strlen(tmp);
        if(tmp[len - 1] == '/')
                tmp[len - 1] = 0;
        for(p = tmp + 1; *p; p++)
                if(*p == '/') {
                        *p = 0;
                        mkdir(tmp, S_IRWXU);
                        *p = '/';
                }
        mkdir(tmp, S_IRWXU);
}

unsigned long long stime_for_pid(string pid){
    char stime[16];
    FILE* fp = popen(("awk '{printf $22}' /proc/" + pid + "/stat").c_str(), "r");
    if (fp == NULL) {
        printf("Failed to run command\n" );
        exit(1);
    }
    fgets(stime, sizeof(stime)-1, fp);
    return atoll(stime);
}


class RulesListFriend
{
public:
  void setPathToProc(RulesList*, string  );
  void setRules(RulesList*, vector<rule>);
};
//allows to set rules directly for the test fixture.
//Otherwise we'd have to use add/modify/mark_active etc to set rules
//But since we aren't supposed to use those methods to set rules because we are testing them
//the workaround is to set rules manually
void RulesListFriend::setRules(RulesList* parent, vector<rule> newrules){
  parent->rules = newrules;
}
void RulesListFriend::setPathToProc(RulesList* parent, string newpath){
  parent->path_to_proc = newpath;
}


class RulesListTest: public ::testing::Test{
public:
  //Create a list of various rules by changing the rules var directly
  RulesListFriend f;
  RulesList* rulesList;
  rule rule1;
  rule rule2;
  rule rule3a;
  rule rule3b;
  rule rule5;
  vector<rule> init_rules;
  RulesListTest(){
    rule1.path = "/rule1/path";
    rule1.perms = ALLOW_ALWAYS;
    rule1.sha = "rule1sha";
    rule1.is_fixed_ctmark = true;
    rule1.ctmark_out = 7777;
    rule1.ctmark_in = 17777;
    rule1.is_permanent = true;

    rule2.path = "/rule2/path";
    rule2.perms = DENY_ALWAYS;
    rule2.sha = "rule2sha";
    rule2.is_fixed_ctmark = false;
    rule2.is_permanent = true;

    //two similar rules which are removed with remove(pid = 'all')
    rule3a.path = "/rule3/path";
    rule3a.perms = ALLOW_ALWAYS;
    rule3a.sha = "rule3sha";
    rule3a.is_permanent = false;
    rule3a.ctmark_out = 27777;
    rule3a.ctmark_in = 37777;

    rule3b.path = "/rule3/path";
    rule3b.perms = ALLOW_ALWAYS;
    rule3b.sha = "rule3sha";
    rule3b.is_permanent = false;
    rule3b.ctmark_out = 47777;
    rule3b.ctmark_in = 57777;

    //an active rule which will be remove()d
    rule5.path = "/rule5/path";
    rule5.perms = ALLOW_ALWAYS;
    rule5.pid = "11223";
    rule5.sha = "rule5sha";
    rule5.is_permanent = false;
    rule5.ctmark_out = 44444;
    rule5.ctmark_in = 54444;

    init_rules.push_back(rule1);
    init_rules.push_back(rule2);
    init_rules.push_back(rule3a);
    init_rules.push_back(rule3b);
    init_rules.push_back(rule5);
    vector<rule> empty;
    rulesList = new RulesList(empty);
    f.setPathToProc(rulesList, "/tmp/");
    f.setRules(rulesList, init_rules);
  }
};


//only using fixture to get rule1 rule2
TEST_F(RulesListTest, constructor){
  vector<rule> r {rule1, rule2};
  RulesList rl(r);
  vector<rule> rulescopy = rl.get_rules_copy();
  ASSERT_EQ(rulescopy.size(), 2);
  for (int i = 0; i < rulescopy.size(); i++){
    ASSERT_NE(rulescopy[i].ctmark_out, 0);
    ASSERT_NE(rulescopy[i].ctmark_in, 0);
    ASSERT_EQ(rulescopy[i].is_permanent, true);
  }
}

TEST_F(RulesListTest, addFromUser){
  system("rm -f -R /tmp/1"); //remove dir from previous test iteration (if any)
  system("rm -f -R /tmp/2");
  system("rm -f /tmp/testexe"); //remove from prev test run
  system("cp testexe /tmp/");

  cout << "subtest1. fail because path is non-existent" << endl;
  ruleslist_rv rv1 = rulesList->addFromUser("/non-existent_path", "1", ALLOW_ONCE, 123456);
  ASSERT_EQ(rv1.success, false);
  ASSERT_EQ(rv1.errormsg == "fopen error in get_sha256_hexdigest", true);

  cout << "subtest2. fail because there is no /proc/<PID>/exe symlink" << endl;
  ruleslist_rv rv2 = rulesList->addFromUser("/tmp/testexe", "1", ALLOW_ONCE, 1);
  ASSERT_EQ(rv2.success, false);
  cout << rv2.errormsg << endl;
  ASSERT_EQ(rv2.errormsg == "_readlink() error", true);

  cout << "subtest3. fail because symlink /proc/<PID>/exe points to a wrong path" << endl;
  _mkdir("/tmp/1");
  symlink("/incorrect/path", "/tmp/1/exe");
  ruleslist_rv rv3 = rulesList->addFromUser("/tmp/testexe", "1", ALLOW_ONCE, 123456);
  ASSERT_EQ(rv3.success, false);
  cout << rv3.errormsg << endl;
  ASSERT_EQ(rv3.errormsg == "/proc/PID/exe points to an unexpected path", true);

  //check that after a running process's exe file is removed from disk, its exe
  //symlink gets a [removed] suffix
  //TODO: implement later or inside a separate test

  cout << "subtest4. fail because /proc/<PID>/stat is not present" << endl;
  _mkdir("/tmp/2");
  symlink("/tmp/testexe", "/tmp/2/exe");
  ruleslist_rv rv4 = rulesList->addFromUser("/tmp/testexe", "2", ALLOW_ONCE, 1);
  ASSERT_EQ(rv4.success, false);
  cout << rv4.errormsg << endl;
  ASSERT_EQ(rv4.errormsg == "stream == NULL in get_starttime", true);

  cout << "subtest5. fail because wrong process starttime" << endl;
  pid_t child_pid = fork();
  if (child_pid == 0){
      execl("/tmp/testexe", (char*)0); // we are in child
  }
  //we are in parent and pid is child's pid
  string pid = to_string(child_pid);
  unix_socket_block("/tmp/lpfwtest" + pid);


  //return path_to_proc to normal because this is a real process
  f.setPathToProc(rulesList, "/proc/");
  ruleslist_rv rv5 = rulesList->addFromUser("/tmp/testexe", pid, ALLOW_ONCE, 1122);
  ASSERT_EQ(rv5.success, false);
  cout << rv5.errormsg << endl;
  ASSERT_EQ(rv5.errormsg == "Starttime change detected", true);

  //TODO: later test _readlink separately
  //make sure that when we delete the running process's exe on disk, its
  // /proc/PID/exe also changes (receives a suffix (deleted) )
  /*
  system("rm -f /tmp/testexe");
  ruleslist_rv rv6 = rulesList->addFromUser("/tmp/testexe", pid, ALLOW_ONCE, 1122);
  ASSERT_EQ(rv6.success, false);
  cout << rv6.errormsg << endl;
  ASSERT_EQ(rv6.errormsg == "/proc/PID/exe points to an unexpected path", true);
  */

  //TODO also test _opendir separately

  cout << "subtest 7. Add a rule" << endl;
  //add a correct rule and check if it was added to rules
  //with correct sha256 and stime etc.
  ruleslist_rv rv7 = rulesList->addFromUser("/tmp/testexe", pid, ALLOW_ALWAYS,
                                            stime_for_pid(pid));
  ASSERT_EQ(rv7.success, true);

  cout << "subtest 8. fail because a duplicate rule is being added" << endl;
  ruleslist_rv rv8 = rulesList->addFromUser("/tmp/testexe", pid, DENY_ALWAYS, stime_for_pid(pid));
  ASSERT_EQ(rv8.success, false);
  cout << rv8.errormsg << endl;
  ASSERT_EQ(rv8.errormsg == "Cannot push duplicate rule", true);
  
  cout << "subtest 9. make sure the rule was added with correct data" << endl;
  //get sha
  char sha[66];
  FILE* fp2 = popen("sha256sum /tmp/testexe | awk \'{printf $1}\' | tr \'a-z\' \'A-Z\'", "r");
  if (fp2 == NULL) {
      printf("Failed to run command\n" );
      exit(1);
  }
  fgets(sha, sizeof(sha)-1, fp2);
  //find the rule
  vector<rule> copy = rulesList->get_rules_copy();
  //one rule is current and one rule is permanent hence +2
  ASSERT_EQ(copy.size(), init_rules.size() + 2);
  bool bFound = false;
  for (int i=0; i < copy.size(); i++){
    if (!(copy[i].path == "/tmp/testexe" && copy[i].pid == pid)) continue;
    bFound = true;
    ASSERT_EQ(copy[i].path == "/tmp/testexe", true);
    ASSERT_EQ(copy[i].pid == pid, true);
    ASSERT_EQ(copy[i].perms == ALLOW_ALWAYS, true);
    ASSERT_EQ(copy[i].sha == string(sha), true);
    ASSERT_EQ(copy[i].ctmark_out > 0, true);
    ASSERT_EQ(copy[i].ctmark_in > 0, true);
    ASSERT_EQ(copy[i].ctmark_in - copy[i].ctmark_out == CTMARK_DELTA, true);
    ASSERT_EQ(copy[i].is_fixed_ctmark, false);
    ASSERT_EQ(copy[i].is_permanent, false);
    ASSERT_EQ(copy[i].is_forked, false);
    ASSERT_EQ(copy[i].parentpid == "0", true);
    ASSERT_EQ(copy[i].stime == stime_for_pid(pid), true);
    ASSERT_EQ(copy[i].pidfdpath == "/proc/" + pid + "/fd/" , true);
    ASSERT_EQ(copy[i].dirstream != NULL, true);
    ASSERT_EQ(copy[i].uid != "", true);
  }
  ASSERT_EQ(bFound, true);
  //also make sure the permanenet rule is present
  bool bFound2 = false;
  for (int i=0; i < copy.size(); i++){
    if (!(copy[i].is_permanent && copy[i].path == "/tmp/testexe")) continue;
    bFound2 = true;
    ASSERT_EQ(copy[i].path == "/tmp/testexe", true);
    ASSERT_EQ(copy[i].perms == ALLOW_ALWAYS, true);
    ASSERT_EQ(copy[i].sha == string(sha), true);
    ASSERT_EQ(copy[i].is_permanent, true);
  }
  ASSERT_EQ(bFound2, true);
  kill(child_pid, SIGUSR1);

}

TEST_F(RulesListTest, pathFindAndAdd){
    /*
    //try to add a rule already in list ret. search active processes
    ruleslist_rv rv1 = rulesList->pathFindAndAdd("existing/path", "111", 123);
    ASSERT_EQ(rv1.success, true);
    ASSERT_EQ(rv1.value == SEARCH_ACTIVE_PROCESSES_AGAIN, true);

    //rules with same path not found
    ruleslist_rv rv2 = rulesList->pathFindAndAdd("existing/path", "111", 123);
    ASSERT_EQ(rv2.success, true);
    ASSERT_EQ(rv2.value == PATH_IN_RULES_NOT_FOUND, true);

    //no proc/<PID>/stat file
    ruleslist_rv rv3 = rulesList->pathFindAndAdd("existing/path", "111", 123);
    ASSERT_EQ(rv3.success, false);
    ASSERT_EQ(rv3.errormsg == "PROCFS_ERROR in get_parent_pid", true);

    */

    f.setPathToProc(rulesList, "/proc/");
    //add a forked process
    pid_t child_pid = fork();
    if (child_pid == 0){
        execl("/tmp/testexe", "fork", (char*)0); // we are in child
    }
    else if (child_pid < 0){
        cout << "fork() failed";
        exit(1);
    }
    else {
        //we are in parent and pid is child's pid
        string pid = to_string(child_pid);
        cout << "blocking and waiting for pid " << pid << endl;
        unix_socket_block("/tmp/lpfwtest" + pid);
        cout << "after socket block" << endl;

        //add parent first
        ruleslist_rv rv1 = rulesList->addFromUser(
                    "/tmp/testexe", pid, ALLOW_ALWAYS, stime_for_pid(pid));
        cout << rv1.errormsg << endl;
        ASSERT_EQ(rv1.success, true);

        //add child
        ifstream f;
        f.open("/tmp/lpfwtest."+ pid + ".child");
        char output[100];
        f >> output;
        f.close();
        cout << "read child pid from file:" << output << endl;
        ruleslist_rv rv2 = rulesList->pathFindAndAdd(
                    "/tmp/testexe", string(output), stime_for_pid(output));
        ASSERT_EQ(rv2.success, true);
        ASSERT_EQ(rv2.value, FORKED_CHILD_ALLOW);




    }



    //add a parent process to rules
    //then add the child to rules


}




/*
TEST_F(RulesListTest, remove){
  //pass incorrect permission
  ruleslist_rv rv5;
  rv5 = rulesList->remove(rule1.path, "3456", DENY_ALWAYS);
  ASSERT_EQ(rv5.success, false);

  //pass non-existant rule
  ruleslist_rv rv6;
  rv6 = rulesList->remove("/rule1/pathnonexistant", "0", DENY_ALWAYS);
  ASSERT_EQ(rv6.success, false);

  //remove rule marked active
  ruleslist_rv rv7;
  rv7 = rulesList->remove(rule5.path, rule5.perms, rule5.pid);
  ASSERT_EQ(rv7.success, true);
  ASSERT_EQ(rv7.ctmarks_to_delete.size(), 1);
  ctmarks c = rv7.ctmarks_to_delete[0];
  ASSERT_EQ(c.in == rule5.ctmark_in && c.out == rule5.ctmark_out, true);

  //remove "all" rule
  ruleslist_rv rv8;
  rv8 = rulesList->remove(rule3a.path, rule3a.perms, "all");
  ASSERT_EQ(rv8.success, true);
  ASSERT_EQ(rv8.ctmarks_to_delete.size(), 2);
  ASSERT_EQ(rulesList->get_rules_copy().size(), init_rules.size()-3);
}
*/
