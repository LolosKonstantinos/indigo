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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib-2.0/glib.h>
#include <glib-2.0/glib/gstdio.h>
#include <fcntl.h>
#include <errno.h>
#include <log.h>

#ifdef __linux__
#include <sys/types.h>
#endif

#include "binary_tree.h"
#include "indigo_errors.h"
#include "indigo_types.h"

int load_username(char username[MAX_USERNAME_LEN * sizeof(uint32_t) + 1])
{
    FILE *fp = NULL;
    int file_descriptor;
    size_t ret;
    size_t size;
    char filename[PATH_MAX];

    get_source_dir(filename);
    strcat(filename, "/"INDIGO_USER_DIR);
    g_mkdir_with_parents(filename, 0755);
    strcat(filename, "/"INDIGO_USERNAME_FILE_NAME);

    if (access(filename, F_OK)) {
        //if the file does not exist we create it
        log_warn("[load_username] username file does not exist and thus it is created");
        file_descriptor = open(filename, O_RDWR | O_CREAT, S_IRUSR + S_IWUSR + S_IRGRP + S_IWGRP + S_IROTH);
        if (file_descriptor == -1) {
            log_error("[load_username] failed to open file %s as username file | return %d | errno %d",
                filename , INDIGO_ERROR_CAN_NOT_OPEN_FILE, errno);
            return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
        }
        fp = fdopen(file_descriptor,"r+");
        if (!fp) {
            log_error("[load_username] failed to open file %s as username file | return %d | errno %d",
                filename , INDIGO_ERROR_CAN_NOT_OPEN_FILE, errno);
            close(file_descriptor);
            return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
        }
    }
    else {
        fp = fopen(filename, "r+");
        if (!fp) {
            log_error("[load_username] failed to open file %s as username file | return %d | errno %d",
                filename , INDIGO_ERROR_CAN_NOT_OPEN_FILE, errno);
            return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
        }
    }
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size == 0) {
        strcpy(username, "FAT_AND_UGLY");
        fprintf(fp, "%s",username);
        log_info("[load_username] user probably tried to delete username, "
                 "they shouldn't mess with config dir if they can't do it right");
        fclose(fp);
        return 1;
    }

    memset(username, 0, sizeof(uint32_t) * MAX_USERNAME_LEN);

    ret = fread(username, 1, MAX_USERNAME_LEN * sizeof(uint32_t), fp);
    if (ret != size) {

        fclose(fp);
        log_error("[load_username] fread read less bytes than username file | return %d | errno %d", INDIGO_ERROR, errno);
        return INDIGO_ERROR;
        // todo: handle error better
    }
    fclose(fp);
    return 0;
}
int validate_username(char username[MAX_USERNAME_LEN  * sizeof(uint32_t) +1 ])
{
    return g_utf8_validate(username, MAX_USERNAME_LEN * sizeof(uint32_t), NULL);
}
int sanitize_username(char username[MAX_USERNAME_LEN * sizeof(uint32_t) + 1])
{
    char *valid_username;
    valid_username = g_utf8_make_valid(username, MAX_USERNAME_LEN + 1);
    if (!valid_username) {
        log_error("[sanitize_username] g_utf8_make_valid() failed. probably not enough memory");
        return -1;
    }
    strncpy(username, valid_username, MAX_USERNAME_LEN * sizeof(uint32_t));
    username[MAX_USERNAME_LEN * sizeof(uint32_t)] = '\0';
    g_free(valid_username);
    return 0;
}

int set_username(char username[MAX_USERNAME_LEN  * sizeof(uint32_t) + 1])
{
    FILE *fp = NULL;
    size_t ret;
    char filename[32] = INDIGO_USER_DIR;

    g_mkdir_with_parents(INDIGO_USER_DIR, 0755);

    fp = fopen(strcat(filename, INDIGO_USERNAME_FILE_NAME), "wb");
    if (!fp) {
        log_error("[set_username] failed to open file %s as username file | return %d | errno %d",
            filename, INDIGO_ERROR_CAN_NOT_OPEN_FILE, errno);
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }
    username[MAX_USERNAME_LEN * sizeof(uint32_t)] = '\0';

    ret = fwrite(username, 1, strlen(username) + 1, fp);
    if (ret != strlen(username) + 1) {
        log_error("[set_username] failed to write username (%s) to file | return %d | errno %d", username, INDIGO_ERROR, errno);
        fclose(fp);
        return INDIGO_ERROR;
        // todo: handle error better
    }
    fclose(fp);
    return 0;
}
int load_known_keys(tree_t *known_keys)
{
    size_t ret;
    void *salt;
    char file_name[PATH_MAX];
    FILE *fp_kkeys;
    known_key_t known_key;

    if (!known_keys) {
        log_error("[load_known_keys] null parameter");
        return -1;
    }

    get_source_dir(file_name);
    file_name[PATH_MAX -1] = '\0';
    strncat(file_name, "/"INDIGO_CONFIG_DIR, PATH_MAX - strlen(file_name));
    g_mkdir_with_parents(file_name, 0755);
    strncat(file_name, "/"INDIGO_KNOWN_KEYS_FILE_NAME, PATH_MAX - strlen(file_name));
    if (access(file_name, F_OK)) {
        log_warn("[load_known_keys] known key file was not found | return %d | errno %d",
            INDIGO_ERROR_FILE_NOT_FOUND, errno);
        return INDIGO_ERROR_FILE_NOT_FOUND;
    }

    fp_kkeys = fopen(file_name, "r");
    if (!fp_kkeys) {
        log_error("[load_known_keys] failed to open file %s | return %d | errno %d", file_name, INDIGO_ERROR_FILE_NOT_FOUND, errno);
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }

    while (ret = fread(&known_key, 40, 1, fp_kkeys), ret == 1) {
        known_keys->insert(known_keys, &known_key);
    }
    fclose(fp_kkeys);
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
    FILE *fp;
    char file_name[PATH_MAX];
    size_t ret;

    get_source_dir(file_name);
    file_name[PATH_MAX -1] = '\0';
    strncat(file_name, "/"INDIGO_CONFIG_DIR"/"INDIGO_KNOWN_KEYS_FILE_NAME, PATH_MAX - strlen(file_name));

    fp = fopen(file_name, "a");
    if (!fp) {
        log_error("[save_known_key] failed to open file %s | return %d | errno %d", file_name, INDIGO_ERROR_CAN_NOT_OPEN_FILE, errno);
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }
    ret = fwrite(key, crypto_sign_PUBLICKEYBYTES, 1, fp);
    if (ret != 1) {
        fclose(fp);
        log_error("[save_known_key] failed to write known key to file | return %d | errno %d", INDIGO_ERROR, errno);
        return INDIGO_ERROR;
    }
    ret = fwrite(&status, sizeof(uint64_t), 1, fp);
    if (ret != 1) {
        fclose(fp);
        log_error("[save_known_key] failed to write known key status to file | return %d | errno", INDIGO_ERROR, errno);
        return INDIGO_ERROR;
    }
    fclose(fp);
    return 0;
}
int ins_known_key(tree_t *known_keys, unsigned char key[crypto_sign_PUBLICKEYBYTES], uint64_t status)
{
    int ret = insert_known_key(known_keys, key, status);
    if (ret) {
        log_error("[ins_known_key] failed to insert known key | return %d", ret);
        return ret;
    }
    ret = save_known_key(key, status);
    if (ret) {
        log_error("[ins_known_key] save_known_key() failed to save known key | return %d", ret);
        return ret;
    }
    return 0;
}

int edit_known_key(tree_t *known_keys, unsigned char key[crypto_sign_PUBLICKEYBYTES], uint64_t status)
{
    FILE *fd;
    char *file_name;

    size_t ret;
    known_key_t known_key;
    known_key_t *found_key;
    memcpy(known_key.key, key, crypto_sign_PUBLICKEYBYTES);

    // edit the tree
    ret = known_keys->search_pin(known_keys, &known_key, (void **)&found_key);
    if (ret) {
        log_error("[edit_known_key] search_pin() failed to find key | return %d", INDIGO_ERROR);
        return INDIGO_ERROR;
    }
    found_key->status = status;
    known_keys->search_release(known_keys);

    // edit the file

    file_name = malloc(strlen(INDIGO_CONFIG_DIR) + strlen(INDIGO_KNOWN_KEYS_FILE_NAME) + 1);
    if (file_name == NULL) {
        log_error("[edit_known_key] malloc failed allocating %lld bytes for known keys file name | return %d",
            strlen(INDIGO_CONFIG_DIR) + strlen(INDIGO_KNOWN_KEYS_FILE_NAME) + 1,
            INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    strcpy(file_name, INDIGO_CONFIG_DIR);
    strcat(file_name, INDIGO_KNOWN_KEYS_FILE_NAME);
    fd = fopen(file_name, "r+");
    if (!fd) {
        free(file_name);
        log_error("[edit_known_key] failed to open file %s | return %d | errno %d", file_name, INDIGO_ERROR_CAN_NOT_OPEN_FILE, errno);
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }
    fseek(fd, 0, SEEK_SET);
    while (1) {
        ret = fread(&found_key, sizeof(known_key_t), 1, fd);
        if (ret != 1) {
            if (feof(fd)) {
                memcpy(known_key.key, key, crypto_sign_PUBLICKEYBYTES);
                known_key.status = status;
                fseek(fd, 0, SEEK_END);
                fwrite(&known_key, sizeof(known_key), 1, fd);
                free(file_name);
                return INDIGO_SUCCESS;
            }
            else {
                // well this is an error
                //  TODO: error encountered
                free(file_name);
                log_error("[edit_known_key] error reading from known key file | return %d | errno %d", INDIGO_ERROR, errno);
                return INDIGO_ERROR;
            }
        }
        if (memcmp(key, known_key.key, crypto_sign_PUBLICKEYBYTES) == 0) {
            fseek(fd, -((long)sizeof(uint64_t)), SEEK_CUR);
            ret = fwrite(&status, sizeof(uint64_t), 1, fd);
            if (ret != 1) {
                log_error("[edit_known_key] failed to write known key status to file | return %d | errno %d", INDIGO_ERROR, errno);
                free(file_name);
                return INDIGO_ERROR;
            }
            break;
        }
    }
    free(file_name);
    return 0;
}
int get_source_dir(char path[PATH_MAX])
{
#ifdef _WIN32
    char *dir;
    char *utf8_xpath;
    WCHAR xpath[PATH_MAX];
    DWORD len = GetModuleFileNameW(NULL, xpath, PATH_MAX);
    if (len > 0) {
        utf8_xpath = g_utf16_to_utf8(xpath, -1, NULL, NULL, NULL);
        dir = g_path_get_dirname(utf8_xpath);
        strncpy(path, dir, PATH_MAX - 1);
        g_free(dir);
        g_free(utf8_xpath);
        path[PATH_MAX - 1] = '\0';
        return 0;
    }
    log_error("GetModuleFileNameW() failed to load executables name | return -1");
    return -1;
#endif
#ifdef __linux__
    char *dir;
    char xpath[PATH_MAX];
    ssize_t ret = readlink("/proc/self/exe", xpath, PATH_MAX - 1);
    if (ret == -1) {
        memset(path, 0, PATH_MAX);
        log_error("[get_source_dir] readlink() failed to read /proc/self/exe link | return -1| errno %d", errno);
        return -1;
    }
    xpath[ret] = '\0';
    dir = g_path_get_dirname(xpath);
    strncpy(path, dir, PATH_MAX - 1);
    g_free(dir);
    path[PATH_MAX - 1] = '\0';

    return 0;
#endif
}

int move_to_downloads(char path[PATH_MAX], char new_file_name[NAME_MAX])
{
    char new_path[PATH_MAX];
    char file_serial[65];
#ifdef _WIN32
    const char *profile = getenv("USERPROFILE");
    if (!profile) {
        log_error("getenv failed to get USERPROFILE | return -1");
        return -1;
    }
    snprintf(new_path, PATH_MAX - 1, "%s\\Downloads\\%s", profile, new_file_name);
#else
    const char *home = getenv("HOME");
    if (!home) {
        return -1;
    }
    snprintf(new_path, PATH_MAX - 1, "%s/Downloads/%s", home, new_file_name);
#endif
    new_path[PATH_MAX - 1] = '\0';
    if (rename(path, new_path)) {
        log_error("[move_to_downloads] rename failed to rename %s to %s | return -1 | errno %d", path, new_path, errno);
        return -1;
        // if file already exists we add a (n) at the end
        if (strlen(new_path) >= PATH_MAX - 1) {
            for (uint32_t i = 0; i < UINT_MAX; ++i) {
                snprintf(file_serial, 64, "%x", i);

                // remove the extension if it exists
                // apend the serial
                // apend the extension
                // check if the file exists
            }
        }
    }
    return 0;
}

FILE *load_log_file()
{
    char xpath[PATH_MAX];
    FILE *log_file;

    get_source_dir(xpath);
    strncat(xpath, "/", PATH_MAX - strlen(xpath));
    strncat(xpath, INDIGO_CONFIG_DIR, PATH_MAX - 1);
    xpath[PATH_MAX - 1] = '\0';
    g_mkdir_with_parents(xpath, 0755);
    strncat(xpath, "/", PATH_MAX - strlen(xpath));
    strncat(xpath, INDIGO_LOG_FILE_NAME, PATH_MAX - strlen(xpath));
    xpath[PATH_MAX - 1] = '\0';

    log_file = fopen(xpath, "a+");
    if (!log_file) {
        return NULL;
    }
    return log_file;
}
