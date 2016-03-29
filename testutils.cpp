#include "testutils.h"
#include "unix_socket.h"
#include <string.h> //strlen()
#include <sys/stat.h> // mkdir()
#include <unistd.h> //fork()
#include <iostream> //for cout()

using namespace std;

namespace TestUtils
{
    string forkexec(string exename, bool will_fork_child = false){
        //remove possibly stale exefiles from previous runs
        system(("rm -f /tmp/" + exename).c_str());
        system(("cp testexe /tmp/" + exename).c_str());
        pid_t child_pid = fork();
        if (child_pid == 0){
            if (will_fork_child){
                execl(("/tmp/" + exename).c_str(), "fork", (char*)0); // we are in child
            }
            else {
                execl(("/tmp/" + exename).c_str(), (char*)0);
            }
        }
        else if (child_pid < 0){
            cout << "fork() failed";
            exit(1);
        }
        unix_socket_block("/tmp/lpfwtest" + to_string(child_pid));
        cout << "forkexec returning: " << to_string(child_pid) << endl;
        return to_string(child_pid);
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


    //creates dirs recursively up until the last dir in the path
    void _mkdir(const char *dir) {
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

}


