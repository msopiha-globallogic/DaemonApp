#ifndef SESSION_H
#define SESSION_H

#include "crypto.h"
#include "token.h"

#include <iostream>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <cstdio>

class Session {
public:
    Session(int fd, std::string cert, std::string key) : mFd(fd),
        mPeerCertFileName(cert), mPrivateKeyFileName(key) {}
    ~Session ();

    Token getSessionToken();

private:
    int mFd;
    std::string mPeerCertFileName;
    std::string mPrivateKeyFileName;
    std::vector<unsigned short> mSharedSecret;

    X509 *GetPeerCert();
    HANDSHAKE_REQUEST *GetHandshakeRequest();
    HANDSHAKE_REQUEST *FormHandshakeResponse(long sessionId,
                                             const EC_KEY *key);

    int SetHangshakeResponse(HANDSHAKE_REQUEST *response);
    int VerifyHandshakeRequest(HANDSHAKE_REQUEST *request);
    int DeriveSecret(EC_KEY *privKey, EC_KEY *pubKey,
                     std::vector<unsigned char> &sharedSecret);
    int ProcessHandshake(std::vector<unsigned char> &sharedSecret);

    Token GetToken(std::vector<unsigned char> &sharedKey);
};

#endif // SESSION_H
