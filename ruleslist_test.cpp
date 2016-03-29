#include "gtest/gtest.h"
#include "ruleslist.h"
#include "testutils.h"
#include <fstream>
#include <signal.h> //for kill()
#include <stdio.h>
#include <unistd.h> //for symlink()

using namespace TestUtils;

class RulesListFriend
{
public:
  void setPathToProc(RulesList*, string  );
  void setRules(RulesList*, vector<rule>);
  string _readlink(RulesList* parent, string path);
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
string RulesListFriend::_readlink(RulesList* parent, string path){
  return parent->_readlink(path);
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
  system("rm -f -R /tmp/2");  //remove dir from previous test iteration (if any)

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
  string testexe2pid = forkexec("testexe2");
  ruleslist_rv rv3 = rulesList->addFromUser("/tmp/testexe", testexe2pid, ALLOW_ONCE, 123456);
  kill(atoi(testexe2pid.c_str()), SIGUSR1);
  system("rm -f /tmp/testexe2");
  ASSERT_EQ(rv3.success, false);
  cout << rv3.errormsg << endl;
  ASSERT_EQ(rv3.errormsg == "/proc/PID/exe points to an unexpected path", true);


  cout << "subtest. _readlink() must fail after exe removed from disk" << endl;
  string testexe3pid = forkexec("testexe3");
  string before = f._readlink(rulesList, "/proc/" + testexe3pid + "/exe");
  ASSERT_EQ(before == "/tmp/testexe3", true);
  system("rm -f /tmp/testexe3");
  string after = f._readlink(rulesList, "/proc/" + testexe3pid + "/exe");
  kill(atoi(testexe3pid.c_str()), SIGUSR1);
  ASSERT_EQ(after == "/tmp/testexe3 (deleted)", true);


  cout << "subtest4. fail because /proc/<PID>/stat is not present" << endl;
  system("rm -f -R /tmp/2");
  _mkdir("/tmp/2");
  system("rm -f /tmp/testexe4");
  system("cp testexe /tmp/testexe4");
  symlink("/tmp/testexe4", "/tmp/2/exe");
  f.setPathToProc(rulesList, "/tmp/");
  ruleslist_rv rv4 = rulesList->addFromUser("/tmp/testexe4", "2", ALLOW_ONCE, 1);
  f.setPathToProc(rulesList, "/proc/");
  system("rm -f /tmp/testexe4");
  system("rm -f -R /tmp/2");
  ASSERT_EQ(rv4.success, false);
  cout << rv4.errormsg << endl;
  ASSERT_EQ(rv4.errormsg == "stream == NULL in get_starttime", true);

//TODO need to test when procPIDstat is suddnely unavailable

  cout << "subtest5. fail because wrong process starttime" << endl;
  string testexe5pid = forkexec("testexe5");
  ruleslist_rv rv5 = rulesList->addFromUser("/tmp/testexe5", testexe5pid, ALLOW_ONCE, 1122);
  kill(atoi(testexe5pid.c_str()), SIGUSR1);
  system("rm -f /tmp/testexe5");
  ASSERT_EQ(rv5.success, false);
  cout << rv5.errormsg << endl;
  ASSERT_EQ(rv5.errormsg == "Starttime change detected", true);


  cout << "subtest6. procPIDexe returns wrong path after exe removed from disk" << endl;
  string testexe6pid = forkexec("testexe6");
  system("rm /tmp/testexe6");
  ruleslist_rv rv6 = rulesList->addFromUser("/tmp/testexe", testexe6pid, ALLOW_ONCE, 1122);
  kill(atoi(testexe6pid.c_str()), SIGUSR1);
  ASSERT_EQ(rv6.success, false);
  cout << rv6.errormsg << endl;
  ASSERT_EQ(rv6.errormsg == "/proc/PID/exe points to an unexpected path", true);


  //TODO also test _opendir separately

  cout << "subtest 7. make sure the rule was added with correct data" << endl;
  //add a correct rule and check if it was added to rules
  //with correct sha256 and stime etc.
  string testexe7pid = forkexec("testexe7");
  ruleslist_rv rv7 = rulesList->addFromUser("/tmp/testexe7", testexe7pid,
                                            ALLOW_ALWAYS, stime_for_pid(testexe7pid));
  ASSERT_EQ(rv7.success, true);

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
    if (!(copy[i].path == "/tmp/testexe7" && copy[i].pid == testexe7pid)) continue;
    bFound = true;
    ASSERT_EQ(copy[i].path == "/tmp/testexe7", true);
    ASSERT_EQ(copy[i].pid == testexe7pid, true);
    ASSERT_EQ(copy[i].perms == ALLOW_ALWAYS, true);
    ASSERT_EQ(copy[i].sha == string(sha), true);
    ASSERT_EQ(copy[i].ctmark_out > 0, true);
    ASSERT_EQ(copy[i].ctmark_in > 0, true);
    ASSERT_EQ(copy[i].ctmark_in - copy[i].ctmark_out == CTMARK_DELTA, true);
    ASSERT_EQ(copy[i].is_fixed_ctmark, false);
    ASSERT_EQ(copy[i].is_permanent, false);
    ASSERT_EQ(copy[i].is_forked, false);
    ASSERT_EQ(copy[i].parentpid == "0", true);
    ASSERT_EQ(copy[i].stime == stime_for_pid(testexe7pid), true);
    ASSERT_EQ(copy[i].pidfdpath == "/proc/" + testexe7pid + "/fd/" , true);
    ASSERT_EQ(copy[i].dirstream != NULL, true);
    ASSERT_EQ(copy[i].uid != "", true);
  }
  ASSERT_EQ(bFound, true);
  //also make sure the permanenet rule is present
  bool bFound2 = false;
  for (int i=0; i < copy.size(); i++){
    if (!(copy[i].is_permanent && copy[i].path == "/tmp/testexe7")) continue;
    bFound2 = true;
    ASSERT_EQ(copy[i].path == "/tmp/testexe7", true);
    ASSERT_EQ(copy[i].perms == ALLOW_ALWAYS, true);
    ASSERT_EQ(copy[i].sha == string(sha), true);
    ASSERT_EQ(copy[i].is_permanent, true);
  }
  ASSERT_EQ(bFound2, true);


  cout << "subtest 8. (relies on subtest 7) fail because a duplicate rule is being added" << endl;
  ruleslist_rv rv8 = rulesList->addFromUser("/tmp/testexe7", testexe7pid, DENY_ALWAYS, stime_for_pid(testexe7pid));
  kill(atoi(testexe7pid.c_str()), SIGUSR1);
  system("rm -f /tmp/testexe7");
  ASSERT_EQ(rv8.success, false);
  cout << rv8.errormsg << endl;
  ASSERT_EQ(rv8.errormsg == "Cannot push duplicate rule", true);


}

TEST_F(RulesListTest, pathFindAndAdd){

    cout << "subtest. try to add a rule already in list" << endl;
    string pid1 = forkexec("testexe", true);
    ruleslist_rv rv1 = rulesList->addFromUser("/tmp/testexe", pid1, ALLOW_ALWAYS, stime_for_pid(pid1));
    cout << rv1.errormsg << endl;
    ASSERT_EQ(rv1.success, true);
    ruleslist_rv rv2 = rulesList->pathFindAndAdd("/tmp/testexe", pid1, stime_for_pid(pid1));
    ASSERT_EQ(rv2.success, true);
    ASSERT_EQ(rv2.value == SEARCH_ACTIVE_PROCESSES_AGAIN, true);


    cout << "subtest. rules with same path not found" << endl;
    ruleslist_rv rv3 = rulesList->pathFindAndAdd("/some/path", "111", 123);
    ASSERT_EQ(rv3.success, true);
    ASSERT_EQ(rv3.value == PATH_IN_RULES_NOT_FOUND, true);


    cout << "subtest. no proc/<PID>/stat file" << endl;
    int unusedPID;
    for (unusedPID = 1; unusedPID < 1000; unusedPID++){
        if (kill(unusedPID, 0) == -1 && errno == ESRCH){
            break;//process doesnt exist
        }
    }
    ruleslist_rv rv4 = rulesList->pathFindAndAdd("/tmp/testexe", to_string(unusedPID), 123);
    ASSERT_EQ(rv4.success, false);
    ASSERT_EQ(rv4.errormsg == "PROCFS_ERROR in get_parent_pid", true);


    cout << "subtest. add child of the parent forkexec'd earlier" << endl;
    ifstream f;
    f.open("/tmp/lpfwtest."+ pid1 + ".child");
    char forked_child_pid[6];
    f >> forked_child_pid;
    f.close();
    cout << "read child pid from file:" << forked_child_pid << endl;
    ruleslist_rv rv5 = rulesList->pathFindAndAdd(
                "/tmp/testexe", string(forked_child_pid),
                stime_for_pid(forked_child_pid));
    ASSERT_EQ(rv5.success, true);
    ASSERT_EQ(rv5.value, FORKED_CHILD_ALLOW);
    kill(atoi(pid1.c_str()), SIGUSR1);
    kill(atoi(forked_child_pid), SIGUSR1);

    //TODO if the parent itself is forked, then add as a new instance

    //stime not available while adding


    cout << "subtest. add new instance" << endl;
    string testexe8pid = forkexec("testexe8");
    ruleslist_rv rv6 = rulesList->addFromUser("/tmp/testexe8", testexe8pid,
                           ALLOW_ALWAYS, stime_for_pid(testexe8pid));
    ASSERT_EQ(rv6.success, true);
    cout << "removing inactive process" << endl;
    ruleslist_rv rv7 = rulesList->removeInactive("/tmp/testexe8", ALLOW_ALWAYS, testexe8pid);
    cout << rv7.errormsg << endl;
    ASSERT_EQ(rv7.success, true);

    cout << "subtest. exefile removed" << endl;
    system("rm /tmp/testexe8");
    ruleslist_rv rv8 = rulesList->pathFindAndAdd("/tmp/testexe8", testexe8pid, stime_for_pid(testexe8pid));
    ASSERT_EQ(rv8.success, false);
    ASSERT_EQ(rv8.errormsg, "fopen error in get_sha256_hexdigest");

    cout << "subtest. incorrect exefile hash" << endl;
    ofstream ofs;
    ofs.open("/tmp/testexe8");
    ofs << "random data";
    ofs.close();
    ruleslist_rv rv10 = rulesList->pathFindAndAdd("/tmp/testexe8", testexe8pid, stime_for_pid(testexe8pid));
    system("rm /tmp/testexe8");
    ASSERT_EQ(rv10.success, false);
    ASSERT_EQ(rv10.errormsg, "SHA_DONT_MATCH in addNewInstance");

    system("cp testexe /tmp/testexe8");
    ruleslist_rv rv9 = rulesList->pathFindAndAdd("/tmp/testexe8", testexe8pid, stime_for_pid(testexe8pid));
    ASSERT_EQ(rv9.success, true);
    ASSERT_EQ(rv9.value, NEW_INSTANCE_ALLOW);
    kill(atoi(testexe8pid.c_str()), SIGUSR1);

    cout << "subtest. query user because path in rules not permanent" << endl;
    string testexe9Apid = forkexec("testexe9");
    ruleslist_rv rv11 = rulesList->addFromUser("/tmp/testexe9", testexe9Apid,
                           ALLOW_ONCE, stime_for_pid(testexe9Apid));
    ASSERT_EQ(rv11.success, true);
    string testexe9Bpid = forkexec("testexe9");
    ruleslist_rv rv12 = rulesList->pathFindAndAdd("/tmp/testexe9",
                            testexe9Bpid, stime_for_pid(testexe9Bpid));
    ASSERT_EQ(rv12.success, true);
    ASSERT_EQ(rv12.value, PATH_IN_RULES_FOUND_BUT_PERMS_ARE_ONCE);
    kill(atoi(testexe9Apid.c_str()), SIGUSR1);
    kill(atoi(testexe9Bpid.c_str()), SIGUSR1);

    //TODO test when added process quits and starttime not available

    //TODO check that the rules were added correctly formatted
}

TEST_F(RulesListTest, removeInactive){
    //pass incorrect permissions
    string testexe1pid = forkexec("testexe1", true);
    ruleslist_rv rv1 = rulesList->addFromUser("/tmp/testexe1", testexe1pid,
                           ALLOW_ALWAYS, stime_for_pid(testexe1pid));
    ASSERT_EQ(rv1.success, true);
    ifstream f("/tmp/lpfwtest."+ testexe1pid + ".child");
    stringstream buffer;
    buffer << f.rdbuf();
    f.close();
    string forked_child_pid = buffer.str();

    cout << "child pid is:" << forked_child_pid << endl;
    ruleslist_rv rv11 = rulesList->pathFindAndAdd(
                "/tmp/testexe1", forked_child_pid,
                stime_for_pid(forked_child_pid));
    ASSERT_EQ(rv11.success, true);
    ASSERT_EQ(rv11.value, FORKED_CHILD_ALLOW);
    kill(atoi(testexe1pid.c_str()), SIGUSR1);
    kill(atoi(forked_child_pid.c_str()), SIGUSR1);


    ruleslist_rv rv2 = rulesList->removeInactive("/tmp/testexe1", ALLOW_ONCE, testexe1pid);
    ASSERT_EQ(rv2.success, false);
    ASSERT_EQ(rv2.errormsg == "Caller passed incorrect permission", true);

    //pass nonexisting rule "Failed to find the rule"
    ruleslist_rv rv3 = rulesList->removeInactive("/tmp/nonexisting", ALLOW_ONCE, testexe1pid);
    ASSERT_EQ(rv3.success, false);
    ASSERT_EQ(rv3.errormsg == "Failed to find the rule", true);

    //pass correct rule and check that both it and all of its children were removed
    ruleslist_rv rv4 = rulesList->removeInactive("/tmp/testexe1", ALLOW_ALWAYS, testexe1pid);
    ASSERT_EQ(rv4.success, true);
    vector<rule> rulescopy = rulesList->get_rules_copy();
    bool bProcessOrChildFound = false;
    for (int i=0; i < rulescopy.size(); i++){
        if (rulescopy[i].path != "/tmp/testexe1") continue;
        if (rulescopy[i].pid == testexe1pid || rulescopy[i].parentpid == testexe1pid){
            bProcessOrChildFound = true;
            break;
        }
    }
    ASSERT_EQ(bProcessOrChildFound, false);
    //TODO check the returned ctmarks
}

TEST_F(RulesListTest, removePermanent){
    //fill with rules
    string testexe11pid = forkexec("testexe11", true);
    ruleslist_rv rv1 = rulesList->addFromUser("/tmp/testexe11", testexe11pid,
                           DENY_ALWAYS, stime_for_pid(testexe11pid));
    ASSERT_EQ(rv1.success, true);
    ifstream f("/tmp/lpfwtest."+ testexe11pid + ".child");
    stringstream buffer;
    buffer << f.rdbuf();
    f.close();
    string forked_child_pid = buffer.str();

    cout << "child pid is:" << forked_child_pid << endl;
    ruleslist_rv rv2 = rulesList->pathFindAndAdd(
                "/tmp/testexe11", forked_child_pid,
                stime_for_pid(forked_child_pid));
    ASSERT_EQ(rv2.success, true);
    ASSERT_EQ(rv2.value, FORKED_CHILD_DENY);
    kill(atoi(testexe11pid.c_str()), SIGUSR1);
    kill(atoi(forked_child_pid.c_str()), SIGUSR1);

    //pass incorrect permissions
    ruleslist_rv rv3 = rulesList->removePermanent("/tmp/testexe11", ALLOW_ALWAYS);
    ASSERT_EQ(rv3.success, false);
    ASSERT_EQ(rv3.errormsg == "Wrong permission passed to removePermanent", true);

    //pass nonexistent rule
    ruleslist_rv rv4 = rulesList->removePermanent("/wrong/path", ALLOW_ALWAYS);
    ASSERT_EQ(rv4.success, false);
    ASSERT_EQ(rv4.errormsg == "Could not find a rule among is_permanent", true);

   //pass correct rule. both is_permanent as well as current and forked rules are removed
    ruleslist_rv rv5 = rulesList->removePermanent("/tmp/testexe11", DENY_ALWAYS);
    ASSERT_EQ(rv5.success, true);
    vector<rule> rulescopy = rulesList->get_rules_copy();
    bool bPathFound = false;
    for (int i=0; i < rulescopy.size(); i++){
        if (rulescopy[i].path != "/tmp/testexe11") continue;
        bPathFound = true;
        break;
    }
    ASSERT_EQ(bPathFound, false);

    //TODO make sure it returns correct ctmarks to delete


}

