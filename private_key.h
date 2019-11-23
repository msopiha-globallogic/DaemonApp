#ifndef PRIVATE_KEY_H
#define PRIVATE_KEY_H

#include "aes.h"
#include "crypto.h"

class PrivateKey {
public:
    /* Throws errno as exception */
    PrivateKey(std::string filename, std::string pwd)  throw(int);

    /* Decrypt private key and make signature in this routine. */
    int Sign (std::vector <unsigned char> &data,
              std::vector <unsigned char> &signature);

    ~PrivateKey();

private:
    KEY_BLOB *mKey;
    std::string mPwd;
};

#endif // PRIVATE_KEY_H
