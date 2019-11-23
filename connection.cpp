#include "connection.h"

Connection::~Connection() {
    if (mOpen)
        close(mSockfd);
}

int Connection::StartListening() {
    mSockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (mSockfd <= 0) {
        SetErr(errno);
        return -1;
    }

    mOpen = true;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = static_cast<unsigned short>(htons(mPort));
    if (bind(mSockfd, reinterpret_cast<const struct sockaddr*>(&addr),
             sizeof(addr))) {
        SetErr(errno);
        return -1;
    }

    if (listen(mSockfd, MAX_CONNS)) {
            SetErr(errno);
            return -1;
    }

    return 0;
}

int Connection::GetNextConnection() {
    return accept(mSockfd, nullptr, nullptr);
}

int Connection::GetLastError() {
    return mLastError;
}

std::string Connection::GetLastErrorString() {
    return std::string(strerror(mLastError));
}

void Connection::SetErr(int err) {
    mLastError = err;
}
