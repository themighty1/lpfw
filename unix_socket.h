#ifndef UNIX_SOCKET_H
#define UNIX_SOCKET_H

#include <string>

using namespace std;

void unix_socket_block(string name);
void unix_socket_connect(string name);

#endif // UNIX_SOCKET_H

