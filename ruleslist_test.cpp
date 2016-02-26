#include "gtest/gtest.h"
#include "ruleslist.h"
#include <fstream>
#include <unistd.h> //for symlink()
#include <sys/socket.h>
#include <sys/un.h>

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
  string new1path = "/tmp/new1";
  string new1hash = "2AC8A140BD002C6D2F46A980AEAD578B14D1F36978ABD34825787681FD7E091F";
  ofstream f1(new1path);
  f1 << "rule3";
  f1.close();
  _mkdir("/tmp/3333/fd");

  string new2path = "/rule4";
  string new2pid = "19203";
  string new2perms = ALLOW_ALWAYS;
  string new2sha = "DEADBEEF";
  unsigned long long new2stime = 1234567;
  u_int32_t new2ctmark = 15243;

  system("rm -f -R /tmp/1"); //remove dir from previous test iteration (if any)
  system("rm -f -R /tmp/2");

  cout << "subtest1" << endl;
  //should fail because path is non-existent
  ruleslist_rv rv1 = rulesList->addFromUser("/fail", "1", ALLOW_ONCE, 123456);
  ASSERT_EQ(rv1.success, false);
  ASSERT_EQ(rv1.errormsg == "fopen error in get_sha256_hexdigest", true);

  cout << "subtest2" << endl;
  //fail because there is no /proc/PID/exe entry
  ofstream f2("/tmp/existing_path");
  f2.close();
  ruleslist_rv rv2 = rulesList->addFromUser("/tmp/existing_path", "1", ALLOW_ONCE, 1);
  ASSERT_EQ(rv2.success, false);
  cout << rv2.errormsg << endl;
  ASSERT_EQ(rv2.errormsg == "_readlink() error", true);

  cout << "subtest3" << endl;
  //create a symlink /proc/PID/exe which points to a wrong path
  _mkdir("/tmp/1");
  symlink("/incorrect/path", "/tmp/1/exe");
  ruleslist_rv rv3 = rulesList->addFromUser("/tmp/existing_path", "1", ALLOW_ONCE, 123456);
  ASSERT_EQ(rv3.success, false);
  cout << rv3.errormsg << endl;
  ASSERT_EQ(rv3.errormsg == "/proc/PID/exe points to an unexpected path", true);

  //check that after a running process's exe file is removed from disk, its exe
  //symlink gets a [removed] suffix
  //TODO: implement later or inside a separate test

  cout << "subtest4" << endl;
  //fail because /proc/PID/stat is not present
  ofstream f3("/tmp/existing_path2");
  f3.close();
  _mkdir("/tmp/2");
  symlink("/tmp/existing_path2", "/tmp/2/exe");
  ruleslist_rv rv4 = rulesList->addFromUser("/tmp/existing_path2", "2", ALLOW_ONCE, 1);
  ASSERT_EQ(rv4.success, false);
  cout << rv4.errormsg << endl;
  ASSERT_EQ(rv4.errormsg == "stream == NULL in get_starttime", true);

  cout << "subtest5" << endl;
  //copy a simple exe to /tmp, launch, get pid and pass incorrect stime
  system("rm -f /tmp/testexe"); //remove from prev test run
  system("cp testexe /tmp/");
  pid_t child_pid = fork();
  if (child_pid == 0){
      //child
      cout << "child pid is " << getpid() << endl;
      execl("/tmp/testexe", (char*) 0);
  }
  //we are in parent and pid is child's pid
  string pid = to_string(child_pid);

  //listen for a connection on unix socket
  //accept()ed connection indicates that the exec() child started
  struct sockaddr_un addr;
  string socket_path = "/tmp/lpfwtest" + pid;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path)-1);
  unlink(socket_path.c_str());
  int fd, cl;
  if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
      perror("socket error");
      exit(-1);
    }
  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
      perror("bind error");
      exit(-1);
  }
  if (listen(fd, 5) == -1) {
      perror("listen error");
      exit(-1);
  }
  //will block here until accept()
  if ( (cl = accept(fd, NULL, NULL)) == -1) {
   perror("accept error");
   exit(-1);
 }
 cout << "child started!!!";
  //return path_to_proc to normal as this is a real process
  f.setPathToProc(rulesList, "/proc/");
  ruleslist_rv rv5 = rulesList->addFromUser("/tmp/testexe", pid, ALLOW_ONCE, 1122);
  //terminate the child process
  system(("kill -s USR1 " + pid).c_str());
  ASSERT_EQ(rv5.success, false);
  cout << rv5.errormsg << endl;
  ASSERT_EQ(rv5.errormsg == "Starttime change detected", true);




/*
  //check later that pidfdpath is set correctly and
  //dirstream is NULL and sha is set and ctmark is set
  ruleslist_rv rv2 = rulesList->addFromUser(new2path, new2pid, new2perms, new2stime);
  ASSERT_EQ(rv2.success, true);
  //check later that hashing gave correct result and that ctmarks are assigned
  ruleslist_rv rv3 = rulesList->addFromUser(new1path, "3333", ALLOW_ONCE, 123456);
  ASSERT_EQ(rv3.success, true);
  //a duplicate rule must be rejected
  ruleslist_rv rv4 = rulesList->addFromUser(new1path, "3333", DENY_ONCE, 123456);
  ASSERT_EQ(rv4.success, false);

  vector<rule> copy = rulesList->get_rules_copy();
  ASSERT_EQ(copy.size(), init_rules.size() + 2);
  bool bnew1Found = false;
  bool bnew2Found = false;
  for (int i=0; i < copy.size(); i++){
    if (! bnew1Found && copy[i].path == new1path){
      bnew1Found = true;
      ASSERT_EQ(copy[i].sha == new1hash, true);
      ASSERT_EQ(copy[i].ctmark_out > 0, true);
      ASSERT_EQ(copy[i].ctmark_in > 0, true);
      ASSERT_EQ(copy[i].ctmark_in - copy[i].ctmark_out == CTMARK_DELTA, true);
      continue;
    }
    else if (! bnew2Found && copy[i].path == new2path){
      bnew2Found = true;
      ASSERT_EQ(copy[i].pid == new2pid, true);
      ASSERT_EQ(copy[i].perms == new2perms, true);
      ASSERT_EQ(copy[i].sha == new2sha, true);
      ASSERT_EQ(copy[i].stime == new2stime, true);
      ASSERT_EQ(copy[i].ctmark_out == new2ctmark, true);
      ASSERT_EQ(copy[i].ctmark_in - copy[i].ctmark_out == CTMARK_DELTA, true);
      ASSERT_EQ(copy[i].is_fixed_ctmark, false);
      ASSERT_EQ(copy[i].pidfdpath == ("/tmp/" + new2pid + "/fd/"), true);
      ASSERT_EQ(copy[i].dirstream == NULL, true);
    }
  }
  ASSERT_EQ(bnew1Found && bnew2Found, true);

 */
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
