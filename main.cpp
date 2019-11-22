#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define EC_NID NID_secp521r1

#define AES_GCM_256_IV_SIZE 12
#define AES_GCM_256_KEY_SIZE 32
#define AES_GCM_256_TAG_SIZE 16
#define AES_MODE_ENCRYPT 1
#define AES_MODE_DECRYPT 0

#define MAX_CONNS 1

typedef struct HandshakeRequest {
    ASN1_INTEGER *deviceId;
    ASN1_OCTET_STRING *publicKeyInfo;
    ASN1_OCTET_STRING *signature;
} HANDSHAKE_REQUEST;

ASN1_SEQUENCE(HANDSHAKE_REQUEST) = {
    ASN1_SIMPLE(HANDSHAKE_REQUEST, deviceId, ASN1_INTEGER),
    ASN1_SIMPLE(HANDSHAKE_REQUEST, publicKeyInfo, ASN1_OCTET_STRING),
    ASN1_SIMPLE(HANDSHAKE_REQUEST, signature, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(HANDSHAKE_REQUEST);
IMPLEMENT_ASN1_FUNCTIONS(HANDSHAKE_REQUEST);

typedef struct HandshakeResponse {
    ASN1_OCTET_STRING *publicKeyInfo;
    ASN1_OCTET_STRING *signature;
} HANDSHAKE_RESPONSE;

ASN1_SEQUENCE(HANDSHAKE_RESPONSE) = {
    ASN1_SIMPLE(HANDSHAKE_RESPONSE, publicKeyInfo, ASN1_OCTET_STRING),
    ASN1_SIMPLE(HANDSHAKE_RESPONSE, signature, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(HANDSHAKE_RESPONSE);
IMPLEMENT_ASN1_FUNCTIONS(HANDSHAKE_RESPONSE);

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

class Key {
public:
    /* Throws errno as exception */
    Key(std::string filename, std::string pwd) throw(int) {
        FILE *hFile = fopen(filename.c_str(), "rb");
        if (!hFile)
            throw errno;

        fseek(hFile , 0 , SEEK_END);
        size_t lSize = static_cast<size_t>(ftell(hFile));
        rewind(hFile);

        unsigned char *data = static_cast<unsigned char *>(std::malloc(lSize));
        if (!data) {
            fclose (hFile);
            throw -ENOMEM;
        }

        size_t rSize = fread(data, 1, lSize, hFile);
        fclose(hFile);

        if (lSize != rSize) {
            std::free(data);
            throw -EIO;
        }

        const unsigned char *ptr = data;
        mKey = d2i_KEY_BLOB(nullptr, &ptr, static_cast<long>(lSize));
        std::free(data);

        if (!mKey)
            throw -EINVAL;

        mPwd = pwd;
    }

    ~Key() {
        KEY_BLOB_free(mKey);
    }

private:
    KEY_BLOB *mKey;
    std::string mPwd;

};

struct Token {
    enum SecurityState {
	Permissive = 0,
	Enforced
    } state;
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

int main() {
    Connection con(8080);
    if (con.StartListening())
        std::cout << "Failed to start listening. Err = " << con.GetLastErrorString()
                  << std::endl;
    int confd = con.GetNextConnection();

}
