#include "aes.h"
#include "crypto.h"

AES::AES(std::string password) : mPwd(password){
    mKey.resize(AES_GCM_256_KEY_SIZE);
    SHA256(reinterpret_cast<const unsigned char*>(mPwd.c_str()),
           strlen(mPwd.c_str()), mKey.data());
}

AES::~AES(){
    mKey.clear();
}

void AES::setIv(unsigned char *data, int length) {
    mIv.clear();
    mIv.resize(static_cast<size_t>(length));
    memcpy(mIv.data(), data, static_cast<size_t>(length));
}

std::vector<unsigned char>& AES::getIv () {
    return mIv;
}

void AES::setTag(unsigned char *data, int length) {
    mTag.clear();
    mTag.resize(static_cast<size_t>(length));
    memcpy(mTag.data(), data, static_cast<size_t>(length));
}

std::vector<unsigned char>& AES::getTag () {
    return mTag;
}

int AES::Encrypt(unsigned char *data,
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
    if (!pCryptUpdate(ctx, out, &outLen, data, dataLen) ||
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
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

std::vector <unsigned char>& AES::getKey() {
    return mKey;
}
