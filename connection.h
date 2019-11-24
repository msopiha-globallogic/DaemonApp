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

    void setPwd(std::string &pwd);
    void setKeyFile(std::string &keyFile);
    void setCertFile(std::string &certFile);

    std::string& getCertFile();
    std::string& getKeyFile();
    std::string& getPwdFile();

private:
    bool mOpen;
    int mSockfd;
    int mLastError;
    unsigned short mPort;
    void SetErr(int err);

    std::string mCertFile;
    std::string mKeyFile;
    std::string mPwd;
};

#endif // CONNECTION_H
