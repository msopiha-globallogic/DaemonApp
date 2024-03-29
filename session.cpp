#include "session.h"

#include <memory>

#include "reader.h"
#include "private_key.h"
#include "log.h"
#include <openssl/pem.h>


#define BUF_LEN_DEFAULT 512
#define DEVICE_ID    1234567

ASN1_SEQUENCE(HANDSHAKE_TBS) = {
    ASN1_SIMPLE(HANDSHAKE_TBS, sessionId, ASN1_INTEGER),
    ASN1_SIMPLE(HANDSHAKE_TBS, deviceId, ASN1_INTEGER),
    ASN1_SIMPLE(HANDSHAKE_TBS, publicKeyInfo, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(HANDSHAKE_TBS);
IMPLEMENT_ASN1_FUNCTIONS(HANDSHAKE_TBS);

ASN1_SEQUENCE(HANDSHAKE_REQUEST) = {
    ASN1_SIMPLE(HANDSHAKE_REQUEST, tbs, HANDSHAKE_TBS),
    ASN1_SIMPLE(HANDSHAKE_REQUEST, signature, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(HANDSHAKE_REQUEST);
IMPLEMENT_ASN1_FUNCTIONS(HANDSHAKE_REQUEST);

ASN1_SEQUENCE(SIGNAL_MESSAGE) = {
    ASN1_SIMPLE(SIGNAL_MESSAGE, encryptedSignal, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SIGNAL_MESSAGE, tag, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SIGNAL_MESSAGE, iv, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(SIGNAL_MESSAGE);
IMPLEMENT_ASN1_FUNCTIONS(SIGNAL_MESSAGE);

ASN1_SEQUENCE(SIGNAL_VALUE) = {
    ASN1_SIMPLE(SIGNAL_VALUE, signalValue, ASN1_ENUMERATED),
}ASN1_SEQUENCE_END(SIGNAL_VALUE);
IMPLEMENT_ASN1_FUNCTIONS(SIGNAL_VALUE);

Session::~Session () {
    close(mFd);
}

Token Session::getSessionToken() {
    std::vector<unsigned char> sharedKey;
    if (ProcessHandshake(sharedKey)) {
        return Token();
    }

    return GetToken(sharedKey);
}

HANDSHAKE_REQUEST* Session::GetHandshakeRequest() {
    /*
     * It is not expected here to get big data. So we are not
     * doing any loops here
     */
    std::vector<unsigned char> buf(BUF_LEN_DEFAULT);
    ssize_t bytes = read(mFd, buf.data(), buf.size());
    if (bytes <= 0) {
        LOGE("No data received.");
        return nullptr;
    }

    buf.resize(static_cast<size_t>(bytes));
    const unsigned char *ptr = buf.data();
    return d2i_HANDSHAKE_REQUEST(nullptr, &ptr, bytes);
}

int Session::SetHangshakeResponse(HANDSHAKE_REQUEST *response) {
    int len = i2d_HANDSHAKE_REQUEST(response, nullptr);
    if (len <= 0)
        return -1;

    std::vector<unsigned char> resp(static_cast<size_t>(len));
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

/**
 * Note: We don't do any certificate encryption for demo purpose
 */
X509* Session::GetPeerCert () {
    Reader r(mPeerCertFileName);
    const unsigned char* certPtr = r.GetContent().data();
    size_t certLen = r.GetContent().size();
    return d2i_X509(nullptr, &certPtr, static_cast<long>(certLen));
}

int Session::VerifyHandshakeRequest (HANDSHAKE_REQUEST *request) {
    int ret = -1;
    std::vector<unsigned char> signedData;

    if (ASN1_INTEGER_get(request->tbs->deviceId) != DEVICE_ID)
        return ret;

    int signedLen = i2d_HANDSHAKE_TBS(request->tbs, nullptr);
    if (signedLen <= 0) {
        return ret;
    }

    signedData.resize(static_cast<unsigned long>(signedLen));
    unsigned char *ptr = signedData.data();

    if (i2d_HANDSHAKE_TBS(request->tbs, &ptr) != signedLen) {
        return ret;
    }

    X509 *peerCert = GetPeerCert();
    if (!peerCert) {
        return ret;
    }

    EVP_PKEY *pKey = X509_get0_pubkey(peerCert);
    if (!pKey) {
        X509_free(peerCert);
        return ret;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (!ctx) {
        X509_free(peerCert);
        return ret;
    }

    /* using default signature hashing alg sha256 for demo*/
    if (1 != EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pKey)) {
        goto out;
    }

    if (1 != EVP_DigestVerify(ctx, request->signature->data,
                              static_cast<size_t>(request->signature->length),
                              signedData.data(), signedData.size())) {
        LOGE("Failed to verify signature.");
        goto out;
    }

    ret = 0;
out:
    EVP_MD_CTX_free(ctx);
    X509_free(peerCert);
    return ret;
}

HANDSHAKE_REQUEST* Session::FormHandshakeResponse(long sessionId,
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
    int len = i2o_ECPublicKey(key, nullptr);
    if (len <= 0) {
        LOGE("Failed to serialize EC public key");
        HANDSHAKE_REQUEST_free(response);
        return nullptr;
    }

    std::vector<unsigned char> data;
    data.resize(static_cast<size_t>(len));

    unsigned char *ptr = data.data();
    if (i2o_ECPublicKey(key, &ptr) != len) {
        LOGE("Failed to serialize EC public key");
        HANDSHAKE_REQUEST_free(response);
        return nullptr;
    }

    if (!ASN1_OCTET_STRING_set(response->tbs->publicKeyInfo, data.data(),
                               static_cast<int>(len))) {
        HANDSHAKE_REQUEST_free(response);
        return nullptr;
    }

    int tbsLen = i2d_HANDSHAKE_TBS(response->tbs, nullptr);
    if (tbsLen <= 0) {
        HANDSHAKE_REQUEST_free(response);
        return nullptr;
    }

    std::vector<unsigned char> tbs(static_cast<size_t>(tbsLen));
    ptr = tbs.data();
    if (i2d_HANDSHAKE_TBS(response->tbs, &ptr) != tbsLen) {
        HANDSHAKE_REQUEST_free(response);
        return nullptr;
    }

    std::vector<unsigned char> signature;
    try {
        PrivateKey privKey(mPrivateKeyFileName, mPassword);
        if (privKey.Sign(tbs, signature)) {
            LOGE("Failed to sign response");
            HANDSHAKE_REQUEST_free(response);
            return nullptr;
        }
    }
    catch (int e) {
        LOGE("Failed to read key file - %s", strerror(e));
        return nullptr;
    }

    if (!ASN1_OCTET_STRING_set(response->signature, signature.data(),
                               static_cast<int>(signature.size()))) {
        HANDSHAKE_REQUEST_free(response);
        return nullptr;
    }

    return response;
}

int Session::DeriveSecret(EC_KEY *privKey, EC_KEY *pubKey,
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
        LOGE("Failed to assign private key");
        EC_KEY_free(k);
        goto out;
    }

    k = EC_KEY_dup(pubKey);
    if (!EVP_PKEY_assign_EC_KEY(peerKey, k)) {
        LOGE("Failed to assign peer key");
        EC_KEY_free(k);
        goto out;
    }

    ctx = EVP_PKEY_CTX_new(pKey, nullptr);
    if (!ctx)
        goto out;

    if (EVP_PKEY_derive_init(ctx) != 1) {
        LOGE("Failed to init ctx");
        goto out;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerKey) != 1) {
        LOGE("Failed to set peerkey to context");
        goto out;
    }

    sharedSecret.resize(skeylen);
    if (EVP_PKEY_derive(ctx, sharedSecret.data(), &skeylen) != 1) {
        LOGE("Failed to derive key");
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

int Session::ProcessHandshake(std::vector<unsigned char> &sharedSecret) {
    int ret = -1;
    HANDSHAKE_REQUEST *response = nullptr;
    HANDSHAKE_REQUEST *request = GetHandshakeRequest();

    LOGI("Received incoming request. Verifying...");

    if (!request) {
        LOGE("Failed to receive handshake request");
        return ret;
    }

    const unsigned char *ptr = request->tbs->publicKeyInfo->data;

    if (VerifyHandshakeRequest(request)) {
        LOGE("Failed to verify handshake request");
        HANDSHAKE_REQUEST_free(request);
        return ret;
    }

    LOGI("    Handshake accepted.");

    /*
     * for demo we will not be checking EC params -
     * the default will be use. Also low-level API will be used (EC_KEY
     * insteda of EVP_PKEY
     */
    EC_KEY *peerKey = EC_KEY_new_by_curve_name(EC_NID);
    //std::unique_ptr<EC_KEY, void (*)(EC_KEY*)> peerKey = std::unique_ptr<EC_KEY, void (*)(EC_KEY*)>(EC_KEY_new(), EC_KEY_free);
    EC_KEY *key = EC_KEY_new_by_curve_name(EC_NID);
    //EC_KEY *p = peerKey.get();
    if (!peerKey || !key) {
        goto out;
    }

    if (!EC_KEY_generate_key(key) ||
        !o2i_ECPublicKey(&peerKey, &ptr,
                         static_cast<long>(request->tbs->publicKeyInfo->length))) {
        LOGE("Failed to restore peer public key.");
        goto out;
    }

    response = FormHandshakeResponse(ASN1_INTEGER_get(request->tbs->sessionId),
                                     key);
    if (!response) {
        LOGE("Failed to form handshake response.");
        goto out;
    }

    ret = SetHangshakeResponse(response);

    if (ret) {
        LOGE("Failed to send handshake response");
        goto out;
    }

    LOGI("    Handshake response sent.");

    ret = DeriveSecret(key, peerKey, sharedSecret);

    LOGI("    Shared secret %s", ret ? "failed to derive." : "derived.");
out:
    EC_KEY_free(peerKey);
    EC_KEY_free(key);
    HANDSHAKE_REQUEST_free(request);
    HANDSHAKE_REQUEST_free(response);

    return ret;
}

Token Session::GetToken(std::vector<unsigned char> &sharedKey) {
    Token token;
    std::vector<unsigned char> buf(BUF_LEN_DEFAULT);
    ssize_t bytes = read(mFd, buf.data(), buf.size());
    if (!bytes || bytes < 0) {
        return token;
    }

    buf.resize(static_cast<size_t>(bytes));
    const unsigned char *ptr = buf.data();

    SIGNAL_MESSAGE *message = d2i_SIGNAL_MESSAGE(nullptr, &ptr,
                                                 static_cast<long>(buf.size()));

    if (!message)
        return token;

    AES key(sharedKey);
    key.setIv(message->iv->data, message->iv->length);
    key.setTag(message->tag->data, message->tag->length);

    if (key.Encrypt(message->encryptedSignal->data,
                    message->encryptedSignal->length,
                    AES_MODE_DECRYPT,
                    message->encryptedSignal->data)) {
        SIGNAL_MESSAGE_free(message);
        return token;
    }

    /* the signal already decrypted */
    ptr = message->encryptedSignal->data;
    SIGNAL_VALUE *value = d2i_SIGNAL_VALUE(nullptr, &ptr,
                                           message->encryptedSignal->length);
    SIGNAL_MESSAGE_free(message);
    token.setState(ASN1_ENUMERATED_get(value->signalValue));
    SIGNAL_VALUE_free(value);
    return token;
}
