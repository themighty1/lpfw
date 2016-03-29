#include "gtest/gtest.h"
#include "removeterminated.h"
#include "unix_socket.h"
#include "testutils.h"
#include <fstream>
#include <signal.h> //for kill()
#include <stdio.h>
#include <unistd.h> //for symlink()

using namespace TestUtils;

class RemoveTerminatedFriend
{
public:
  void iteration(RemoveTerminated*);
};
void RemoveTerminatedFriend::iteration(RemoveTerminated* parent){
  parent->iteration();
}

TEST(RemoveTerminatedTest, constructor){
    RemoveTerminatedFriend fr;
    vector<rule> empty;
    RulesList* rulesList = new RulesList(empty);
    RemoveTerminated* rt = new RemoveTerminated(rulesList);

    //launch exe with a fork
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

    //iteratre over rules to make sure 2 rules were added
    vector<rule> rulescopy =rulesList->get_rules_copy();
    ASSERT_EQ(rulescopy.size() == 3, true);

    //kill just the parent, the child will be removed also
    kill(atoi(testexe1pid.c_str()), SIGUSR1);
    sleep(1);

    fr.iteration(rt);
    //only is_permanent rule remains
    vector<rule> rulescopy2 =rulesList->get_rules_copy();
    ASSERT_EQ(rulescopy2.size() == 1, true);

    //kill the child to clean up
    kill(atoi(forked_child_pid.c_str()), SIGUSR1);
}
