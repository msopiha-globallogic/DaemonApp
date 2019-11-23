#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>

#define EC_NID NID_secp521r1

#define AES_GCM_256_IV_SIZE 12
#define AES_GCM_256_KEY_SIZE 32
#define AES_GCM_256_TAG_SIZE 16
#define AES_MODE_ENCRYPT 1
#define AES_MODE_DECRYPT 0
#define BUF_LEN_DEFAULT 256

#define MAX_CONNS 1

typedef struct HANDSHAKE_TBS {
    ASN1_INTEGER *sessionId;
    ASN1_INTEGER *deviceId;
    ASN1_OCTET_STRING *publicKeyInfo;
} HANDSHAKE_TBS;

ASN1_SEQUENCE(HANDSHAKE_TBS) = {
    ASN1_SIMPLE(HANDSHAKE_TBS, sessionId, ASN1_INTEGER),
    ASN1_SIMPLE(HANDSHAKE_TBS, deviceId, ASN1_INTEGER),
    ASN1_SIMPLE(HANDSHAKE_TBS, publicKeyInfo, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(HANDSHAKE_TBS);
IMPLEMENT_ASN1_FUNCTIONS(HANDSHAKE_TBS);

typedef struct HandshakeRequest {
    HANDSHAKE_TBS *tbs;
    ASN1_OCTET_STRING *signature;
} HANDSHAKE_REQUEST;

ASN1_SEQUENCE(HANDSHAKE_REQUEST) = {
    ASN1_SIMPLE(HANDSHAKE_REQUEST, tbs, HANDSHAKE_TBS),
    ASN1_SIMPLE(HANDSHAKE_REQUEST, signature, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(HANDSHAKE_REQUEST);
IMPLEMENT_ASN1_FUNCTIONS(HANDSHAKE_REQUEST);

typedef struct SignalMessage {
    ASN1_OCTET_STRING *encryptedSignal;
    ASN1_OCTET_STRING *iv;
} SIGNAL_MESSAGE;

ASN1_SEQUENCE(SIGNAL_MESSAGE) = {
    ASN1_SIMPLE(SIGNAL_MESSAGE, encryptedSignal, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SIGNAL_MESSAGE, iv, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(SIGNAL_MESSAGE);
IMPLEMENT_ASN1_FUNCTIONS(SIGNAL_MESSAGE);

typedef struct KeyBlob {
    ASN1_OCTET_STRING *encryptedKeyData;
    ASN1_OCTET_STRING *tag;
    ASN1_OCTET_STRING *iv;
} KEY_BLOB;

ASN1_SEQUENCE(KEY_BLOB) = {
    ASN1_SIMPLE(KEY_BLOB, encryptedKeyData, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KEY_BLOB, tag, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KEY_BLOB, iv, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(KEY_BLOB);
IMPLEMENT_ASN1_FUNCTIONS(KEY_BLOB);

typedef struct SignalValue {
    ASN1_ENUMERATED *signalValue;
}SIGNAL_VALUE;

ASN1_SEQUENCE(SIGNAL_VALUE) = {
    ASN1_SIMPLE(SIGNAL_VALUE, signalValue, ASN1_ENUMERATED),
}ASN1_SEQUENCE_END(SIGNAL_VALUE);
IMPLEMENT_ASN1_FUNCTIONS(SIGNAL_VALUE);


class Reader {
public:
    Reader(std::string fileName) : mFileName(fileName), mRead(false) {}
    ~Reader();

    const std::vector <unsigned char> &GetContent() {
        if (!mRead)
            Read();

        return mData;
    }

private:
    std::fstream mFile;
    std::string mFileName;
    std::vector <unsigned char> mData;
    bool mRead;

    void Read () {
        mFile.open(mFileName.c_str(), std::ios::binary);
        if (mFile.fail())
            return;

        long fSize = mFile.tellg();
        mFile.seekg( 0, std::ios::end );
        fSize = mFile.tellg() - fSize;
        mFile.seekg( 0, std::ios::beg );

        mData.resize(static_cast<unsigned long>(fSize));
        char *vecPtr = reinterpret_cast<char*>(mData.data());
        mFile.read(vecPtr, fSize);
        mFile.close();

        mRead = true;
    }
};

class SymmetricKey {
public:
    /* Throws errno as exception */
    SymmetricKey(std::string filename, std::string pwd)  throw(int) {
        Reader r(filename);

        const unsigned char *ptr = r.GetContent().data();
        long lSize = static_cast<long>(r.GetContent().size());
        mKey = d2i_KEY_BLOB(nullptr, &ptr, lSize);

        if (!mKey)
            throw -EINVAL;

        mPwd = pwd;
    }

    ~SymmetricKey() {
        KEY_BLOB_free(mKey);
    }

private:
    KEY_BLOB *mKey;
    std::string mPwd;

};

class Token {
public:
    Token(): mState(SecurityState::Invalid){}
    enum SecurityState {
        Permissive = 0,
        Enforced,
        Invalid
    };

    SecurityState getState() {
        return mState;
    }

    void setState(SecurityState state) {
        mState = state;
    }

private:
    SecurityState  mState;
};

class Connection {
public:
    Connection(unsigned short port) : mOpen(false), mPort(port) {}
    ~Connection() {
        if (mOpen)
            close(mSockfd);
    }

    int StartListening() {
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

    int GetNextConnection() {
        return accept(mSockfd, nullptr, nullptr);
    }

    int GetLastError() {
        return mLastError;
    }

    std::string GetLastErrorString() {
        return std::string(strerror(mLastError));
    }

private:
    bool mOpen;
    int mSockfd;
    int mLastError;
    unsigned short mPort;

    void SetErr(int err) {
        mLastError = err;
    }
};

class Session {
public:
    Session(int fd) : mFd(fd), mPeerkey(nullptr) {}
    ~Session () {
        close(mFd);
        EC_KEY_free(mPeerkey);
    }

    Token getSessionToken() {
        Token token;
        if (ProcessHandshake())
            return token;

        return token;
    }

private:
    int mFd;
    EC_KEY *mPeerkey;

    HANDSHAKE_REQUEST *GetHandshakeRequest() {
        unsigned char buf[BUF_LEN_DEFAULT];
        const unsigned char *ptr = buf;
        size_t bytes = static_cast<size_t>(read(mFd, buf, sizeof(buf)));
        if (!bytes || bytes == sizeof(buf)) {
            return nullptr;
        }

        return d2i_HANDSHAKE_REQUEST(nullptr, &ptr, static_cast<long>(sizeof(buf)));
    }

    X509 *GetPeerCert () {
        Reader r("cert");
        const unsigned char* certPtr = r.GetContent().data();
        size_t certLen = r.GetContent().size();
        return d2i_X509(nullptr, &certPtr, static_cast<long>(certLen));
    }

    int VerifyHandshakeRequest (HANDSHAKE_REQUEST * request,
                                X509 *peerCert) {

    }

    int ProcessHandshake() {
        /*
         * It is not expected here to get big data. So we are not
         * doing any loops here
         */

        HANDSHAKE_REQUEST * request = GetHandshakeRequest();
        if (!request)
            return -1;

        X509 *cert = GetPeerCert();
        if (!cert)
            return -1;



        /*EC_KEY_oct2key*/

        return 0;
    }

    int PopulateToken (Token &token) {
        return 0;
    }
};

int main() {
    Connection con(8080);
    if (con.StartListening())
        std::cout << "Failed to start listening. Err = " << con.GetLastErrorString()
                  << std::endl;
    Session s(con.GetNextConnection());
    Token t = s.getSessionToken();
}
