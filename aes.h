#ifndef AES_H
#define AES_H

#include <iostream>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <cstdio>

/* For demo version we are not thinking of rewriting keys in memory after usage */
class AES {
public:
    AES(std::vector<unsigned char> &key) : mKey(key) {}
    AES(std::string password);
    ~AES();

    void setIv(unsigned char *data, int length);
    std::vector<unsigned char>& getIv();
    void setTag(unsigned char *data, int length);
    std::vector<unsigned char>& getTag ();

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
                unsigned char *out);
private:
    std::string mPwd;
    std::vector<unsigned char> mIv;
    std::vector<unsigned char> mTag;
    std::vector<unsigned char> mKey;

    std::vector <unsigned char> &getKey();
};

#endif // AES_H
