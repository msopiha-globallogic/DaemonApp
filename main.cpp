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
#define DEVICE_ID    1234567

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

/* For demo version we are not thinking of rewriting keys in memory after usage */
class AES {
public:
    AES(std::string password) : mPwd(password){}
    ~AES(){}
    void setIv(unsigned char *data, int length) {
        mIv.clear();
        mIv.resize(static_cast<size_t>(length));
        memcpy(mIv.data(), data, static_cast<size_t>(length));
    }

    std::vector<unsigned char>& getIv () {
        return mIv;
    }

    void setTag(unsigned char *data, int length) {
        mTag.clear();
        mTag.resize(static_cast<size_t>(length));
        memcpy(mTag.data(), data, static_cast<size_t>(length));
    }

    std::vector<unsigned char>& getTag () {
        return mTag;
    }

    /**
     * @brief               Encrypts/decrypts the data.
     *
     * @note                Encrypted/decrypted data is written in the same buffer as input data.
     *
     * @param data          Data to encrypt.
     * @param dataLen       Data length.
     * @param mode          AES_MODE_ENCRYPT or AES_MODE_DECRYPT
     * @return              0 on success, -1 on failure
     */
    int Encrypt(unsigned char *data,
                const int dataLen,
                const int mode,
                unsigned char *out) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outLen = 0, ret = -1;
        if (!ctx)
            return -1;

        int (*pCryptInit)(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                          const unsigned char *, const unsigned char *) =
                mode == AES_MODE_ENCRYPT ? EVP_EncryptInit : EVP_DecryptInit;

        int (*pCryptUpdate)(EVP_CIPHER_CTX *, unsigned char *,
                            int *, const unsigned char *, int) =
                mode == AES_MODE_ENCRYPT ? EVP_EncryptUpdate : EVP_DecryptUpdate;

        int (*pCryptFinal)(EVP_CIPHER_CTX *, unsigned char *, int *) =
                mode == AES_MODE_ENCRYPT ? EVP_EncryptFinal : EVP_DecryptFinal;

        if (!pCryptInit(ctx, EVP_aes_256_gcm(), nullptr, nullptr)) {
            goto err;
        }

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 static_cast<int>(mIv.size()),
                                 nullptr)) {
            goto err;
        }

        if (mode == AES_MODE_DECRYPT &&
            !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                 static_cast<int>(mTag.size()),
                                 mTag.data())) {
                goto err;
        }

        if (!pCryptInit(ctx, nullptr, getKey().data(), mIv.data())) {
            goto err;
        }

        /*
         * Normally we should do the encipherment by blocks in while(..) loop.
         * In current scenarion no big data is expected, so all input can be consumed
         * in a single update call. This also explains funtion parameters and design.
         */
        if (!pCryptUpdate(ctx, data, &outLen, out, dataLen) ||
             outLen != dataLen) {
            goto err;
        }

        /* AES GCM is not modifying anything on final call */
        if (!pCryptFinal(ctx, out + outLen, &outLen)) {
            goto err;
        }

        if (mode == AES_MODE_ENCRYPT) {
            unsigned char tag[AES_GCM_256_TAG_SIZE];
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_256_TAG_SIZE,
                                     tag)) {
                goto err;
            }

            setTag(tag, static_cast<int>(sizeof(tag)));
        }

        ret = 0;

    err:
        EVP_CIPHER_CTX_free(ctx);
        return ret;
    }

private:
    std::string mPwd;
    std::vector<unsigned char> mIv;
    std::vector<unsigned char> mTag;

    std::vector <unsigned char> getKey () {
        std::vector<unsigned char> key(AES_GCM_256_KEY_SIZE);

        SHA256(reinterpret_cast<const unsigned char*>(mPwd.c_str()),
               strlen(mPwd.c_str()), key.data());

        return key;
    }


};

class Reader {
public:
    Reader(std::string fileName) : mFileName(fileName), mRead(false) {}
    ~Reader() {}

    const std::vector <unsigned char> &GetContent() {
        if (!mRead)
            Read();

        return mData;
    }

private:
    std::ifstream mFile;
    std::string mFileName;
    std::vector <unsigned char> mData;
    bool mRead;

    void Read () {
        mFile.open(mFileName.c_str(), std::ios::binary);

        if (mFile.fail()) {
            return;
        }

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

class PrivateKey {
public:
    /* Throws errno as exception */
    PrivateKey(std::string filename, std::string pwd)  throw(int) {
        Reader r(filename);

        const unsigned char *ptr = r.GetContent().data();
        long lSize = static_cast<long>(r.GetContent().size());
        mKey = d2i_KEY_BLOB(nullptr, &ptr, lSize);

        if (!mKey)
            throw -EINVAL;

        mPwd = pwd;
    }

    /* Decrypt private key and make signature in this routine. */
    int Sign (std::vector <unsigned char> &data,
              std::vector <unsigned char> &signature) {
        AES aesKey(mPwd);
        std::vector <unsigned char> decryptedEcKey(static_cast<unsigned long>
                                                   (mKey->encryptedKeyData->length));

        aesKey.setIv(mKey->iv->data, mKey->iv->length);
        aesKey.setTag(mKey->tag->data, mKey->iv->length);
        if (aesKey.Encrypt(mKey->encryptedKeyData->data,
                           mKey->encryptedKeyData->length,
                           AES_MODE_DECRYPT,
                           decryptedEcKey.data())) {
            std::cout << "Failed to make AES decryption\n";
            return -1;
        }

        EC_KEY *ecKey = EC_KEY_new();
        if (!ecKey)
            return -1;

        if (!EC_KEY_oct2priv(ecKey, decryptedEcKey.data(), decryptedEcKey.size())) {
            EC_KEY_free(ecKey);
            return -1;
        }

        EVP_PKEY *pKey = EVP_PKEY_new();
        if (!pKey) {
            EC_KEY_free(ecKey);
            return -1;
        }

        if (!EVP_PKEY_assign_EC_KEY(pKey, ecKey)) {
            EC_KEY_free(ecKey);
            EVP_PKEY_free(pKey);
            return -1;
        }

        int ret = -1;
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pKey, nullptr);
        if (!EVP_PKEY_sign_init(ctx)) {
            goto out;
        }

        if (!EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256())) {
            goto out;
        }

        size_t sigLen;

        if (EVP_PKEY_sign(ctx, nullptr, &sigLen, data.data(), data.size()) != 1) {
            goto out;
        }

        signature.resize(sigLen);
        if (EVP_PKEY_sign(ctx, signature.data(), &sigLen, data.data(), data.size()) != 1) {
            signature.clear();
            goto out;
        }

        ret = 0;

out:
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pKey);
        return ret;
    }

    ~PrivateKey() {
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
    Session(int fd, std::string cert, std::string key) : mFd(fd),
        mPeerCertFileName(cert), mPrivateKeyFileName(key) {}
    ~Session () {
        close(mFd);
    }

    Token getSessionToken() {
        Token token;
        std::vector<unsigned char> sharedKey;
        if (ProcessHandshake(sharedKey))
            return token;

        return token;
    }

private:
    int mFd;
    std::string mPeerCertFileName;
    std::string mPrivateKeyFileName;
    std::vector<unsigned short> mSharedSecret;

    HANDSHAKE_REQUEST *GetHandshakeRequest() {
        /*
         * It is not expected here to get big data. So we are not
         * doing any loops here
         */
        unsigned char buf[BUF_LEN_DEFAULT];
        const unsigned char *ptr = buf;
        size_t bytes = static_cast<size_t>(read(mFd, buf, sizeof(buf)));
        if (!bytes || bytes == sizeof(buf)) {
            return nullptr;
        }

        return d2i_HANDSHAKE_REQUEST(nullptr, &ptr, static_cast<long>(sizeof(buf)));
    }

    int SetHangshakeResponse(HANDSHAKE_REQUEST *response) {
        int len = i2d_HANDSHAKE_REQUEST(response, nullptr);
        if (len <= 0)
            return -1;

        std::vector<unsigned char> resp(static_cast<unsigned long>(len));
        unsigned char *ptr = resp.data();
        if (i2d_HANDSHAKE_REQUEST(response, &ptr) != len)
            return -1;
        int bytes = static_cast<int>(write(mFd, resp.data(),
                                     static_cast<size_t>(len)));

        if (bytes != len) {
            return -1;
        }

        return 0;
    }

    X509 *GetPeerCert () {
        Reader r(mPeerCertFileName);
        const unsigned char* certPtr = r.GetContent().data();
        size_t certLen = r.GetContent().size();
        return d2i_X509(nullptr, &certPtr, static_cast<long>(certLen));
    }

    int VerifyHandshakeRequest (HANDSHAKE_REQUEST *request) {
        int ret = -1;
        std::vector<unsigned char> signedData;

        if (ASN1_INTEGER_get(request->tbs->deviceId) != DEVICE_ID)
            return ret;

        int signedLen = i2d_HANDSHAKE_TBS(request->tbs, nullptr);
        if (signedLen <= 0) {
            return ret;
        }

        unsigned char *ptr = signedData.data();

        signedData.resize(static_cast<unsigned long>(signedLen));
        if (i2d_HANDSHAKE_TBS(request->tbs, &ptr) != signedLen) {
            return ret;
        }

        X509 *peerCert = GetPeerCert();
        if (!peerCert) {
            return -1;
        }

        EVP_PKEY *pKey = X509_get0_pubkey(peerCert);
        if (!pKey) {
            X509_free(peerCert);
            return ret;
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pKey, nullptr);
        if (!ctx) {
            X509_free(peerCert);
            return ret;
        }

        if (!EVP_PKEY_verify_init(ctx)) {
            goto out;
        }

        /* using default signature hashing alg sha256 for demo*/
        if (!EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256())) {
            goto out;
        }

        if(EVP_PKEY_verify(ctx,
                           request->signature->data,
                           static_cast<size_t>(request->signature->length),
                           signedData.data(),
                           static_cast<size_t>(signedLen)) != 1)
            goto out;

        ret = 0;
out:
        EVP_PKEY_CTX_free(ctx);
        X509_free(peerCert);
        return ret;
    }

    HANDSHAKE_REQUEST *FormHandshakeResponse(long sessionId,
                                             const EC_KEY *key) {
        HANDSHAKE_REQUEST *response = HANDSHAKE_REQUEST_new();
        if (!response) {
            return nullptr;
        }

        if (!ASN1_INTEGER_set(response->tbs->sessionId, sessionId) ||
            !ASN1_INTEGER_set(response->tbs->deviceId, DEVICE_ID)) {
            HANDSHAKE_REQUEST_free(response);
            return nullptr;
        }
        size_t len = EC_KEY_key2buf(key, POINT_CONVERSION_COMPRESSED, nullptr,
                                    nullptr);

        std::vector<unsigned char> data;
        data.resize(len);

        unsigned char *ptr = data.data();
        if (EC_KEY_key2buf(key, POINT_CONVERSION_COMPRESSED, &ptr,
                           nullptr) != len) {
            HANDSHAKE_REQUEST_free(response);
            return nullptr;
        }

        if (!ASN1_OCTET_STRING_set(response->tbs->publicKeyInfo, data.data(),
                                   static_cast<int>(len))) {
            HANDSHAKE_REQUEST_free(response);
            return nullptr;
        }

        int signedLen = i2d_HANDSHAKE_TBS(response->tbs, nullptr);
        if (signedLen <= 0) {
            HANDSHAKE_REQUEST_free(response);
            return nullptr;
        }
        std::vector<unsigned char> tbs(len);
        ptr = tbs.data();
        if (i2d_HANDSHAKE_TBS(response->tbs, &ptr) != signedLen) {
            HANDSHAKE_REQUEST_free(response);
            return nullptr;
        }

        std::vector<unsigned char> signature;
        PrivateKey privKey("key", "password");
        if (privKey.Sign(tbs, signature)) {
            HANDSHAKE_REQUEST_free(response);
            return nullptr;
        }

        if (!ASN1_OCTET_STRING_set(response->signature, signature.data(),
                                   static_cast<int>(signature.size()))) {
            HANDSHAKE_REQUEST_free(response);
            return nullptr;
        }

        return response;
    }

    int DeriveSecret(EC_KEY *privKey, EC_KEY *pubKey,
                     std::vector<unsigned char> &sharedSecret) {
        EVP_PKEY *pKey = EVP_PKEY_new();
        EVP_PKEY *peerKey = EVP_PKEY_new();
        EVP_PKEY_CTX *ctx = nullptr;
        int ret = -1;
        EC_KEY *k = nullptr;
        size_t skeylen = AES_GCM_256_KEY_SIZE;

        if (!pKey || !peerKey) {
            goto out;
        }

        /*
         * We need to duplicate EC keys because assigned keys
         * will be released with releasing EVP_PKEYS, so the caller
         * won't be confused by destroyed objects.
         *
         * Doing this step-by-step not to loose memory.
         */

        k = EC_KEY_dup(privKey);
        if (!EVP_PKEY_assign_EC_KEY(pKey, k)) {
            EC_KEY_free(k);
            goto out;
        }

        k = EC_KEY_dup(pubKey);
        if (!EVP_PKEY_assign_EC_KEY(peerKey, k)) {
            EC_KEY_free(k);
            goto out;
        }

        ctx = EVP_PKEY_CTX_new(pKey, nullptr);
        if (!ctx)
            goto out;

        if (EVP_PKEY_derive_init(ctx) != 1)
            goto out;

        if (EVP_PKEY_derive_set_peer(ctx, peerKey) != 1)
            goto out;

        sharedSecret.resize(skeylen);
        if (EVP_PKEY_derive(ctx, sharedSecret.data(), &skeylen)) {
            sharedSecret.clear();
            goto out;
        }

        ret = 0;
out:
        EVP_PKEY_free(pKey);
        EVP_PKEY_free(peerKey);
        EVP_PKEY_CTX_free(ctx);
        return ret;
    }

    int ProcessHandshake(std::vector<unsigned char> &sharedSecret) {
        int ret = -1;
        HANDSHAKE_REQUEST * response = nullptr;
        HANDSHAKE_REQUEST * request = GetHandshakeRequest();

        if (!request)
            return ret;

        if (!VerifyHandshakeRequest(request)) {
            HANDSHAKE_REQUEST_free(request);
            return ret;
        }

        /*
         * for demo we will not be checking EC params -
         * the default will be use. Also low-level API will be used (EC_KEY
         * insteda of EVP_PKEY
         */
        EC_KEY *peerKey = EC_KEY_new();
        EC_KEY *key = EC_KEY_new_by_curve_name(EC_NID);
        if (!peerKey || !key) {
            goto out;
        }

        if (!EC_KEY_generate_key(key) ||
            !EC_KEY_oct2key(peerKey, request->tbs->publicKeyInfo->data,
                            static_cast<size_t>(request->tbs->publicKeyInfo->length),
                            nullptr)) {
            goto out;
        }


        response = FormHandshakeResponse(ASN1_INTEGER_get(request->tbs->sessionId),
                                         key);
        if (!response) {
            goto out;
        }

        ret = SetHangshakeResponse(response);
        HANDSHAKE_REQUEST_free(response);

        if (ret) {
            goto out;
        }

        ret = DeriveSecret(key, peerKey, sharedSecret);
out:
        EC_KEY_free(peerKey);
        EC_KEY_free(key);
        HANDSHAKE_REQUEST_free(request);
        HANDSHAKE_REQUEST_free(response);

        return ret;
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
    Session s(con.GetNextConnection(), "cert", "key");
    Token t = s.getSessionToken();
}
