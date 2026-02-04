//
// Created by Constantin on 10/08/2025.
//

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H



#include <stdint.h>
#include <sodium.h>

//todo move these in indigo_errors
#define INDIGO_FILE_NOT_FOUND 0x02
#define INDIGO_FILE_NOT_AUTHORIZED 0x03

#define INDIGO_PSW_HASH_TIMELIMIT_UPPER 5
#define INDIGO_PSW_HASH_TIMELIMIT_LOWER 3
#define INDIGO_NONCE_SIZE 16

#define INDIGO_CRYPTO_DIR               "config/crypto/"
#define INDIGO_PSW_DIR                  "config/crypto/psw/"
#define INDIGO_KEY_DIR                  "config/crypto/key/"
#define INDIGO_SIGN_KEY_FILE_NAME       "sign.dat"
#define INDIGO_PSW_HASH_FILE_NAME       "psw-hash.txt"
#define INDIGO_PSW_HASH_SETTINGS_FILE   "psw-hash-settings.dat"

typedef struct PSW_HASH_SETTINGS PSW_HASH_SETTINGS;

struct SIGNING_KEY_PAIR {
    unsigned char public[crypto_sign_PUBLICKEYBYTES];
    unsigned char secret[crypto_sign_SECRETKEYBYTES];
};
typedef struct SIGNING_KEY_PAIR SIGNING_KEY_PAIR;

/*derive a symmetric key based on the user password*/
int derive_master_key(const char* psw, uint64_t psw_len, void** master_key);

int create_psw_salt(char overwrite);
int load_psw_salt(unsigned char** salt);
int psw_salt_exists();

int create_key_derivation_settings();
int save_key_derivation_settings(uint8_t mem_cost, uint8_t time_cost);
int load_key_derivation_settings(PSW_HASH_SETTINGS *settings);
int key_derivation_settings_exist();

int save_password_hash(const char* password, uint64_t psw_len);
int load_password_hash(char** hash);
int cmp_password_hash(const char* psw, uint64_t psw_len);
int password_hash_exists();

int create_signing_key_pair(void *master_key);
int load_signing_key_pair(SIGNING_KEY_PAIR *key_pair,const unsigned char* master_key);
int sign_buffer(const SIGNING_KEY_PAIR *key_pair, const unsigned char* buffer, uint64_t buffer_len,
                                                  unsigned char *signed_buffer, uint64_t *signed_len);
int signing_key_pair_exists();
int delete_signing_key_pair();

#endif //CRYPTO_UTILS_H