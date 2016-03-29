#ifndef TESTUTILS
#define TESTUTILS

#include <string>

using namespace std;

namespace TestUtils
{
    string forkexec(string exename, bool will_fork_child = false);
    unsigned long long stime_for_pid(string pid);
    void _mkdir(const char *dir);
}


#endif // TESTUTILS

