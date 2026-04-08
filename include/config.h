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

#ifndef INDIGO_CONFIG_H
#define INDIGO_CONFIG_H

#include <indigo_types.h>
#include <binary_tree.h>

/*THIS LIBRARY CONTAINS ALL FUNCTIONS AND TYPES CONCERNING USER AND PROGRAM DATA MANAGEMENT*/

/*USERNAME FUNCTIONS*/
int load_username(wchar_t username[MAX_USERNAME_LEN]);
int set_username(wchar_t username[MAX_USERNAME_LEN]);
int validate_username(wchar_t username[MAX_USERNAME_LEN]);
int sanitize_username(wchar_t username[MAX_USERNAME_LEN]);

/*SETTINGS STRUCTURES AND DEFINITIONS*/
typedef struct settings_t {
    char example;
}settings_t;

/*SETTINGS FUNCTIONS*/
int load_settings(settings_t * settings);
int set_settings(settings_t * settings, uint64_t option, void *value);

/*KNOWN PUBLIC KEYS STRUCTURES*/
typedef struct known_key_t {
    uint32_t status;                                //the status of the key, is it trusted? dangerous? suspicious? IDK.
    unsigned char key[crypto_sign_PUBLICKEYBYTES];  //the key
} known_key_t;

/*KNOWN PUBLIC KEYS FUNCTIONS*/
//load all keys that have been verified, and trusted or deemed dangerous, in the past.
int load_known_keys(tree_t * known_keys);
//save the given key in the keys file with the given status
int save_known_key(unsigned char key[crypto_sign_PUBLICKEYBYTES], uint64_t status);
//insert the key in the tree without entering it to the key file
int insert_known_key(known_key_t known_keys, unsigned char key[crypto_sign_PUBLICKEYBYTES], uint64_t status);
//insert and save the key and status, to the tree and key file respectively
int ins_known_key(known_key_t known_keys, unsigned char key[crypto_sign_PUBLICKEYBYTES], uint64_t status);

static FORCE_INLINE int key_cmp(void *k1, void *k2) {
    return memcmp(((known_key_t *)k1)->key, ((known_key_t *)k2)->key, crypto_sign_PUBLICKEYBYTES);
}
#endif //INDIGO_CONFIG_H