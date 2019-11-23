#include "private_key.h"
#include "reader.h"
#include <errno.h>

ASN1_SEQUENCE(KEY_BLOB) = {
    ASN1_SIMPLE(KEY_BLOB, encryptedKeyData, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KEY_BLOB, tag, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KEY_BLOB, iv, ASN1_OCTET_STRING),
}ASN1_SEQUENCE_END(KEY_BLOB);
IMPLEMENT_ASN1_FUNCTIONS(KEY_BLOB);

/* Throws errno as exception */
PrivateKey::PrivateKey(std::string filename, std::string pwd)  throw(int) {
    Reader r(filename);

    const unsigned char *ptr = r.GetContent().data();
    long lSize = static_cast<long>(r.GetContent().size());
    mKey = d2i_KEY_BLOB(nullptr, &ptr, lSize);

    if (!mKey)
        throw -EINVAL;

    mPwd = pwd;
}

/* Decrypt private key and make signature in this routine. */
int PrivateKey::Sign (std::vector <unsigned char> &data,
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

PrivateKey::~PrivateKey() {
    KEY_BLOB_free(mKey);
}