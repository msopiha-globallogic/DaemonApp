#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define EC_NID NID_secp521r1

#define AES_GCM_256_IV_SIZE 12
#define AES_GCM_256_KEY_SIZE 32
#define AES_GCM_256_TAG_SIZE 16
#define AES_MODE_ENCRYPT 1
#define AES_MODE_DECRYPT 0

typedef struct HANDSHAKE_TBS {
    ASN1_INTEGER *sessionId;
    ASN1_INTEGER *deviceId;
    ASN1_OCTET_STRING *publicKeyInfo;
} HANDSHAKE_TBS;

typedef struct HandshakeRequest {
    HANDSHAKE_TBS *tbs;
    ASN1_OCTET_STRING *signature;
} HANDSHAKE_REQUEST;

typedef struct SignalMessage {
    ASN1_OCTET_STRING *encryptedSignal;
    ASN1_OCTET_STRING *tag;
    ASN1_OCTET_STRING *iv;
} SIGNAL_MESSAGE;

typedef struct KeyBlob {
    ASN1_OCTET_STRING *encryptedKeyData;
    ASN1_OCTET_STRING *tag;
    ASN1_OCTET_STRING *iv;
} KEY_BLOB;

typedef struct SignalValue {
    ASN1_ENUMERATED *signalValue;
}SIGNAL_VALUE;

#endif // CRYPTO_H
