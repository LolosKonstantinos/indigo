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

#include <config.h>
#include <sodium/crypto_sign.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib-2.0/glib.h>
#include <glib-2.0/glib/gstdio.h>

#include "binary_tree.h"
#include "indigo_errors.h"
#include "indigo_types.h"

int load_username(wchar_t username[MAX_USERNAME_LEN])
{
    size_t ret;
    int size;
    FILE *fd = fopen(strcat(INDIGO_USER_DIR, INDIGO_USERNAME_FILE_NAME), "rb");
    if (!fd) {
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }
    fseek(fd, 0, SEEK_END);
    size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    memset(username, 0, sizeof(wchar_t) * MAX_USERNAME_LEN);

    ret = fread(username, 1, MAX_USERNAME_LEN * sizeof(wchar_t), fd);
    if (ret != size) {

        fclose(fd);
        return INDIGO_ERROR;
        // todo: handle error better
    }
    return 0;
}

int set_username(wchar_t username[MAX_USERNAME_LEN])
{
    size_t ret;
    FILE *fd = fopen(strcat(INDIGO_USER_DIR, INDIGO_USERNAME_FILE_NAME), "wb");
    if (!fd) {
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }
    ret = fwrite(username, 1, MAX_USERNAME_LEN * sizeof(wchar_t), fd);
    if (ret != MAX_USERNAME_LEN) {
        fclose(fd);
        return INDIGO_ERROR;
        // todo: handle error better
    }
    fclose(fd);
    return 0;
}
int load_known_keys(tree_t *known_keys)
{
    int ret;
    void *salt;
    char *file_name;
    FILE *fp_kkeys;
    known_key_t known_key;

    if (!known_keys)
        return -1;

    file_name = malloc(strlen(INDIGO_CONFIG_DIR) + strlen(INDIGO_KNOWN_KEYS_FILE_NAME) + 1);
    if (file_name == NULL) {
        return 1;
    }
    strcpy(file_name, INDIGO_CONFIG_DIR);
    strcat(file_name, INDIGO_KNOWN_KEYS_FILE_NAME);

    if (access(file_name, F_OK)) {
        g_mkdir_with_parents(INDIGO_CONFIG_DIR, 0755);
        free(file_name);
        return INDIGO_ERROR_FILE_NOT_FOUND;
    }
    fp_kkeys = fopen(file_name, "wr");
    if (!fp_kkeys) {
        free(file_name);
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }

    while (ret = fread(&known_key, 40, 1, fp_kkeys), ret == 1) {
        known_keys->insert(known_keys, &known_key);
    }

    return 0;
}
int insert_known_key(tree_t *known_keys, unsigned char key[crypto_sign_PUBLICKEYBYTES], uint64_t status)
{
    known_key_t known_key;
    memcpy(known_key.key, key, crypto_sign_PUBLICKEYBYTES);
    known_key.status = status;
    return known_keys->insert(known_keys, &known_key);
}
int save_known_key(unsigned char key[crypto_sign_PUBLICKEYBYTES], uint64_t status)
{
    FILE *fd;
    char *file_name;
    int ret;

    file_name = malloc(strlen(INDIGO_CONFIG_DIR) + strlen(INDIGO_KNOWN_KEYS_FILE_NAME) + 1);
    if (file_name == NULL) {
        return 1;
    }
    strcpy(file_name, INDIGO_CONFIG_DIR);
    strcat(file_name, INDIGO_KNOWN_KEYS_FILE_NAME);
    fd = fopen(file_name, "a");
    if (!fd) {
        free(file_name);
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }
    free(file_name);
    ret = fwrite(key, crypto_sign_PUBLICKEYBYTES, 1, fd);
    if (ret != 1) {
        fclose(fd);
        return INDIGO_ERROR;
    }
    ret = fwrite(&status, sizeof(uint64_t), 1, fd);
    if (ret != 1) {
        fclose(fd);
        return INDIGO_ERROR;
    }
    fclose(fd);
    return 0;
}
int ins_known_key(tree_t *known_keys, unsigned char key[crypto_sign_PUBLICKEYBYTES], uint64_t status)
{
    int ret = insert_known_key(known_keys, key, status);
    if (ret)
        return ret;
    ret = save_known_key(key, status);
    if (ret)
        return ret;
    return 0;
}
