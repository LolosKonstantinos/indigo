//
// Created by Constantin on 14/08/2025.
//

#ifndef KEYGEN_H
#define KEYGEN_H

#include <openssl/evp.h>
#include <stdint.h>

#define INDIGO_CRYPTO_DIR "config/crypto"
#define INDIGO_PSW_DIR "config/crypto/psw"
#define INDIGO_KEY_DIR "config/crypto/key"

#define INDIGO_DEFAULT_SALT_SIZE 8
#define INDIGO_DEFAULT_MASTER_KEY_SIZE 32
#define INDIGO_DEFAULT_IV_LEN 12
#define INDIGO_DEFAULT_TAG_LEN 16


int derive_master_key(const char* psw, const uint32_t psw_len, void** master_key, uint32_t* key_len);

int create_psw_salt(char overwrite);
int load_psw_salt(unsigned char** salt);

int create_rsa_key_pair(const char *psw, const uint32_t psw_len, char overwrite);
int load_rsa_key_pair(const char *psw, const uint32_t psw_len, EVP_PKEY** rsa_key, uint32_t* key_len);
int delete_rsa_key_pair();

int save_password();
int load_password();
int cmp_password();

#endif //KEYGEN_H
