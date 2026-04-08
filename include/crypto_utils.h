/*Copyright (c) 2026 Lolos Konstantinos

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H



#include <stdint.h>
#include <sodium.h>
#include "indigo_types.h"

//todo use sodium one time authentication with the master key on important config files
//todo move these in indigo_errors
#define INDIGO_FILE_NOT_FOUND 0x02
#define INDIGO_FILE_NOT_AUTHORIZED 0x03

#define INDIGO_PSW_HASH_TIMELIMIT_UPPER 5
#define INDIGO_PSW_HASH_TIMELIMIT_LOWER 3

typedef struct PSW_HASH_SETTINGS PSW_HASH_SETTINGS;

struct signing_key_pair_t {
    unsigned char public[crypto_sign_PUBLICKEYBYTES];
    unsigned char secret[crypto_sign_SECRETKEYBYTES];
};
typedef struct signing_key_pair_t signing_key_pair_t;

typedef struct auth_key_pair_t {
    unsigned char public[crypto_box_PUBLICKEYBYTES];
    unsigned char secret[crypto_box_SECRETKEYBYTES];
}auth_key_pair_t;

typedef struct session_key_pair_t {
    unsigned char public[crypto_box_PUBLICKEYBYTES];
    unsigned char secret[crypto_box_SECRETKEYBYTES];
}session_key_pair_t;

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
int load_signing_key_pair(signing_key_pair_t *key_pair,const unsigned char* master_key);
int sign_buffer(const signing_key_pair_t *key_pair, const unsigned char* buffer, uint64_t buffer_len,
                                                  unsigned char *signed_buffer, uint64_t *signed_len);
int signing_key_pair_exists();
int delete_signing_key_pair();


int encrypt_packet(packet_t *packet
                   ,unsigned char tk[crypto_kx_SESSIONKEYBYTES]
                   , const unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]);
int decrypt_packet(packet_t *packet,unsigned char rk[crypto_kx_SESSIONKEYBYTES]);
int nonce_increment(unsigned char *nonce, size_t nonce_len, uint64_t increment);
#endif //CRYPTO_UTILS_H