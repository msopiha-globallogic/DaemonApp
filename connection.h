#ifndef CONNECTION_H
#define CONNECTION_H

#include <iostream>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <cstdio>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#define MAX_CONNS 1

class Connection {
public:
    Connection(unsigned short port) : mOpen(false), mPort(port) {}
    ~Connection();

    int StartListening();
    int GetNextConnection();
    int GetLastError();
    std::string GetLastErrorString();

private:
    bool mOpen;
    int mSockfd;
    int mLastError;
    unsigned short mPort;
    void SetErr(int err);
};

#endif // CONNECTION_H
