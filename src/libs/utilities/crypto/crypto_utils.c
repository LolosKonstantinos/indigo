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

#include "crypto_utils.h"
#include "config.h"
#include "indigo_errors.h"
#include "indigo_types.h"
#include <glib-2.0/glib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <sodium.h>
#include <unistd.h>
#include <errno.h>
#include <log.h>
#ifdef _WIN32
#include <profileapi.h>
#include <sysinfoapi.h>
#else
#include <sys/sysinfo.h>
#include <limits.h>
#endif



struct PSW_HASH_SETTINGS {
    unsigned char mem_cost;
    unsigned char time_cost;
};

int derive_master_key(const char *psw, const uint64_t psw_len, void **master_key)
{
    uint64_t mem_cost = crypto_pwhash_MEMLIMIT_MIN;
    unsigned char time_cost = crypto_pwhash_OPSLIMIT_MIN;
    unsigned char *out_key = NULL;
    unsigned char *salt = NULL;
    PSW_HASH_SETTINGS psw_settings;
    int ret;

    if (psw == NULL || master_key == NULL) {
        log_error("psw or master key is NULL | return 2");
        return 2;
    }

    ret = load_key_derivation_settings(&psw_settings);
    if (ret != 0) {
        *master_key = NULL;
        log_error("load_key_derivation_settings() failed with %d | return %d", ret, INDIGO_ERROR_INCOMPATIBLE_FILE);
        return INDIGO_ERROR_INCOMPATIBLE_FILE; // possible file changed to
                                               // incompatible values
    }

    mem_cost = psw_settings.mem_cost;
    time_cost = psw_settings.time_cost;

    ret = load_psw_salt(&salt);
    if (ret == -3) {
        *master_key = NULL;
        log_error("load_psw_salt() failed with %d | return %d", ret, INDIGO_ERROR_INCOMPATIBLE_FILE);
        return INDIGO_ERROR_INCOMPATIBLE_FILE; // possible file changed to
                                               // incompatible values
    }
    if (ret == INDIGO_ERROR_FILE_NOT_FOUND) {
        *master_key = NULL;
        log_error("load_key_derivation_settings() failed with %d | return %d", ret, INDIGO_ERROR_INCOMPATIBLE_FILE);
        return INDIGO_ERROR_FILE_NOT_FOUND;
    }

    if (psw_len <= crypto_pwhash_PASSWD_MIN || psw_len >= crypto_pwhash_PASSWD_MAX) {
        log_error("password length is not compatible %d | return -1", psw_len);
        goto cleanup;
    }

    out_key = sodium_malloc(crypto_secretbox_KEYBYTES);
    if (!out_key) {
        log_error("sodium_malloc() failed allocating %lld bytes for master key | return -1", crypto_secretbox_KEYBYTES);
        goto cleanup;
    }
    // printf("DEBUG: %p %lld %p %u %lld\n",psw, psw_len, salt, time_cost,
    // mem_cost);
    fflush(stdin);
    ret = crypto_pwhash(out_key, crypto_secretbox_KEYBYTES, psw, psw_len, salt, time_cost, 1 << mem_cost,
                        crypto_pwhash_ALG_ARGON2ID13);
    if (ret == -1) {
        log_error("crypto_pwhash() failed | return -1");
        goto cleanup;
    }

    // make the master key inaccessible
    sodium_mprotect_readonly(out_key);

    *master_key = out_key;

    free(salt);
    // printf("DEBUG:master key derived\n");
    return 0;

cleanup:
    sodium_free(out_key);
    free(salt);
    *master_key = NULL;
    return -1;
}

int create_psw_salt(const char overwrite)
{
    void *salt;
    char *file_name;
    FILE *fp_salt;
    char *init_cwd;
    char xpath[PATH_MAX];

    if (get_source_dir(xpath)) {
        log_error("get_source_dir() failed | return %d" ,INDIGO_ERROR);
        return INDIGO_ERROR;
    }
    init_cwd = g_get_current_dir();
    chdir(xpath);

    file_name = malloc(strlen(INDIGO_PSW_DIR) + strlen("/salt.dat") + 1);
    if (file_name == NULL) {
        chdir(init_cwd);
        g_free(init_cwd);
        log_error("malloc failed allocating %lld bytes for salt file name",strlen(INDIGO_PSW_DIR) + strlen("/salt.dat") + 1 );
        return 1;
    }
    strcpy(file_name, INDIGO_PSW_DIR);
    strcat(file_name, "/salt.dat");

    if (overwrite == 0 && access(file_name, F_OK) == 0) {
        chdir(init_cwd);
        g_free(init_cwd);
        free(file_name);
        log_error("file %s does not exist | return %d | errno", file_name, INDIGO_ERROR_FILE_NOT_FOUND, errno);
        return INDIGO_ERROR_FILE_NOT_FOUND;
    }

    g_mkdir_with_parents(INDIGO_PSW_DIR, 0755);

    fp_salt = fopen(file_name, "wb");
    if (fp_salt == NULL) {
        chdir(init_cwd);
        g_free(init_cwd);
        free(file_name);
        log_error("failed to open file %s | return 1 | errno %d", file_name, errno);
        return 1;
    }

    salt = malloc(crypto_pwhash_SALTBYTES);
    if (salt == NULL) {
        chdir(init_cwd);
        g_free(init_cwd);
        free(file_name);
        fclose(fp_salt);
        log_error("malloc failed allocating %lld bytes for salt | return %d",
            crypto_pwhash_SALTBYTES,INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    randombytes_buf(salt, crypto_pwhash_SALTBYTES);

    fwrite(salt, crypto_pwhash_SALTBYTES, 1, fp_salt);

    chdir(init_cwd);
    g_free(init_cwd);
    fclose(fp_salt);
    free(file_name);
    free(salt);
    return 0;
}

int load_psw_salt(unsigned char **salt)
{
    char *file_name;
    FILE *fp_salt;
    uint32_t salt_len;

    if (salt == NULL) {
        log_error("salt is null");
        return INDIGO_ERROR_INVALID_PARAM;
    }

    file_name = malloc(strlen(INDIGO_PSW_DIR) + strlen("/salt.dat") + 1);
    if (file_name == NULL) {
        log_error("malloc failed allocating %lld bytes for salt file name | return %d",
            strlen(INDIGO_PSW_DIR) + strlen("/salt.dat") + 1,INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    strcpy(file_name, INDIGO_PSW_DIR);
    strcat(file_name, "/salt.dat");

    if (access(file_name, F_OK) != 0) {
        free(file_name);
        *salt = NULL;
        log_error("file %s does not exist | return %d | errno %d",
            file_name, INDIGO_ERROR_FILE_NOT_FOUND, errno);
        return INDIGO_ERROR_FILE_NOT_FOUND;
    }

    fp_salt = fopen(file_name, "rb");
    if (fp_salt == NULL) {
        free(file_name);
        // todo check errno and return the right error
        *salt = NULL;
        log_error("error opening file %s | return %d | errno %d",
            file_name, INDIGO_ERROR_CAN_NOT_OPEN_FILE, errno);
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }

    fseek(fp_salt, 0, SEEK_END);
    salt_len = ftell(fp_salt);
    fseek(fp_salt, 0, SEEK_SET);

    if (salt_len != crypto_pwhash_SALTBYTES) {
        free(file_name);
        fclose(fp_salt);
        log_error("salt length %d is not %d bytes thus incompatible | return -3", salt_len, crypto_pwhash_SALTBYTES);
        return -3;
    }

    *salt = malloc(salt_len);
    if (*salt == NULL) {
        free(file_name);
        fclose(fp_salt);
        log_error("malloc failed allocating %lld for salt | return 1", salt_len);
        return 1;
    }

    fread(*salt, salt_len, 1, fp_salt);

    fclose(fp_salt);
    free(file_name);
    return 0;
}

int psw_salt_exists()
{
    char file_name[32] = INDIGO_PSW_DIR;
    strcat(file_name, "/salt.dat");

    if (access(file_name, F_OK) == 0) {
        return 1;
    }
    return 0;
}

int create_key_derivation_settings()
{
#ifdef _WIN32
    char *init_cwd;
    char xpath[PATH_MAX];
    char filename[48];
    LARGE_INTEGER freq;
    LARGE_INTEGER start_time;
    LARGE_INTEGER end_time;
    LARGE_INTEGER elapsed_time;
    double elapsed_usec;
    double mean_elapsed = 0;
    int i;
    int ret;

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char out_key[crypto_secretbox_KEYBYTES];
    unsigned char psw[15];

    uint64_t time_cost = 3;
    uint64_t mem_cost;
    uint8_t max_mem_cost;

    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
    randombytes_buf(psw, 15);

    MEMORYSTATUSEX ram = {0};
    size_t total_mem;

    FILE *fp;

    PSW_HASH_SETTINGS settings;

    ram.dwLength = sizeof(ram);
    GlobalMemoryStatusEx(&ram);
    total_mem = ram.ullTotalPhys;
    max_mem_cost = floor(log2((double)total_mem / 4));
    if (max_mem_cost > 30) {
        max_mem_cost = 30;
    }
    if (max_mem_cost < 13) {
        return -max_mem_cost;
    }
    mem_cost = max_mem_cost;

    for (int j = 0; j < 5; j++) {
        mean_elapsed = 0;
        for (i = 0; i < 3; i++) {
            QueryPerformanceFrequency(&freq);     // sets the tick frequency
            QueryPerformanceCounter(&start_time); // sets the tick count at the start

            ret = crypto_pwhash(out_key, crypto_secretbox_KEYBYTES, (char *)psw, 15, salt, time_cost,
                                ((size_t)1) << mem_cost, crypto_pwhash_ALG_ARGON2ID13);

            QueryPerformanceCounter(&end_time); // sets the tick count at the end
            if (ret == -1) {
                return -2;
            }

            elapsed_time.QuadPart = end_time.QuadPart - start_time.QuadPart;
            elapsed_usec = (double)elapsed_time.QuadPart * 1000000;
            elapsed_usec /= (double)freq.QuadPart;
            mean_elapsed += elapsed_usec;
        }
        mean_elapsed /= i * 1000000;
        if (mean_elapsed < INDIGO_PSW_HASH_TIMELIMIT_UPPER && mean_elapsed > INDIGO_PSW_HASH_TIMELIMIT_LOWER) {
            break;
        }
        if (mean_elapsed < INDIGO_PSW_HASH_TIMELIMIT_LOWER) {
            if (mem_cost < max_mem_cost) {
                mem_cost++;
            }
            else {
                time_cost++;
            }
        }
        if (mean_elapsed > INDIGO_PSW_HASH_TIMELIMIT_UPPER) {
            if (mem_cost > 13) {
                mem_cost--;
            }
            else if (time_cost > 1) {
                time_cost--;
            }
            else {
                break;
            }
        }
    }
#else
    int ret;
    char filename[48];
    uint64_t time_cost = 3;
    uint64_t mem_cost;
    uint8_t max_mem_cost;
    PSW_HASH_SETTINGS settings;
    FILE *fp;
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char out_key[crypto_secretbox_KEYBYTES];
    unsigned char psw[15];
    struct timespec start = {0};
    struct timespec end = {0};
    uint64_t elapsed_time;
    uint64_t mean_elapsed;
    long page_size;
    long available_pages;
    int i;
    char *init_cwd;
    char xpath[PATH_MAX];

    page_size = sysconf(_SC_PAGESIZE);
    available_pages = sysconf(_SC_AVPHYS_PAGES);
    max_mem_cost = floor(log2((double)(page_size * available_pages) / 4));
    if (max_mem_cost > 30) {
        max_mem_cost = 30;
    }
    if (max_mem_cost < 13) {
        log_error("total available memory (%lld bytes) bellow minimum (%lld bytes)"
                  " hashing requirements for hashing | return %d",
            available_pages * page_size, 1 << 13, max_mem_cost);
        return -max_mem_cost;
    }
    mem_cost = max_mem_cost;

    for (int j = 0; j < 5; j++) {
        mean_elapsed = 0;
        for (i = 0; i < 3; i++) {
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
            ret = crypto_pwhash(out_key, crypto_secretbox_KEYBYTES, (char *)psw, 15, salt, time_cost,
                                ((size_t)1) << mem_cost, crypto_pwhash_ALG_ARGON2ID13);

            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
            if (ret == -1) {
                log_error("crypto_pwhash failed | return -2");
                return -2;
            }
            elapsed_time = ((end.tv_sec - start.tv_sec) * 1000000000) + (end.tv_nsec - start.tv_nsec);
            mean_elapsed += elapsed_time / 1000000000;
        }
        mean_elapsed /= 3;

        if (mean_elapsed < INDIGO_PSW_HASH_TIMELIMIT_UPPER && mean_elapsed > INDIGO_PSW_HASH_TIMELIMIT_LOWER) {
            break;
        }
        if (mean_elapsed < INDIGO_PSW_HASH_TIMELIMIT_LOWER) {
            if (mem_cost < max_mem_cost) {
                mem_cost++;
            }
            else {
                time_cost++;
            }
        }
        if (mean_elapsed > INDIGO_PSW_HASH_TIMELIMIT_UPPER) {
            if (mem_cost > 13) {
                mem_cost--;
            }
            else if (time_cost > 1) {
                time_cost--;
            }
            else {
                break;
            }
        }
    }

#endif

    init_cwd = g_get_current_dir();
    if (get_source_dir(xpath)) {
        log_error("get_source_dir failed | return %d", INDIGO_ERROR);
        return INDIGO_ERROR;
    }
    chdir(xpath);

    settings.mem_cost = (char)mem_cost;
    settings.time_cost = (char)time_cost;
    g_mkdir_with_parents(INDIGO_PSW_DIR, 0755);
    // printf("debug: memcost-> 1<<%lld, timecost->  %lld, mean_elapsed->%lf
    // \n",mem_cost,time_cost, mean_elapsed);
    strcpy(filename, INDIGO_PSW_DIR);
    strcat(filename, "/");
    strcat(filename, INDIGO_PSW_HASH_SETTINGS_FILE);
    fp = fopen(filename, "wb");
    if (fp == NULL) {
        chdir(init_cwd);
        g_free(init_cwd);
        log_error("failed to open file %s | return %d | errno %d", filename, INDIGO_ERROR_CAN_NOT_OPEN_FILE, errno);
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }
    fwrite(&settings, sizeof(PSW_HASH_SETTINGS), 1, fp);

    chdir(init_cwd);
    g_free(init_cwd);
    fclose(fp);
    return 0;
}

int save_key_derivation_settings(uint8_t mem_cost, uint8_t time_cost)
{
    char filename[48] = INDIGO_PSW_DIR;
    PSW_HASH_SETTINGS settings;
    char *init_cwd;
    char xpath[PATH_MAX];

    init_cwd = g_get_current_dir();
    if (get_source_dir(xpath)) {
        log_error("get_source_dir failed | return %d", INDIGO_ERROR);
        return INDIGO_ERROR;
    }
    chdir(xpath);

    strcat(filename, "/");
    strcat(filename, INDIGO_PSW_HASH_SETTINGS_FILE);
    settings.mem_cost = mem_cost;
    settings.time_cost = time_cost;

    g_mkdir_with_parents(INDIGO_PSW_DIR, 0755);

    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        chdir(init_cwd);
        g_free(init_cwd);
        log_error("failed to open file %s | return %d | errno %d", filename, INDIGO_ERROR_CAN_NOT_OPEN_FILE, errno);
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }
    fwrite(&settings, sizeof(PSW_HASH_SETTINGS), 1, fp);

    chdir(init_cwd);
    g_free(init_cwd);
    fclose(fp);
    return 0;
}

int load_key_derivation_settings(PSW_HASH_SETTINGS *settings)
{
    char filename[48] = INDIGO_PSW_DIR;
    FILE *fp;
    size_t len;

    strcat(filename, "/");
    strcat(filename, INDIGO_PSW_HASH_SETTINGS_FILE);

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        log_error("can not open file %s for hash settings | return %d | errno %d", filename, INDIGO_ERROR_CAN_NOT_OPEN_FILE, errno);
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    } // todo but check errno to be sure

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len != sizeof(PSW_HASH_SETTINGS)) {
        fclose(fp);
        log_error("hash settings file has incompatible length %d | return %d", len, INDIGO_ERROR_INCOMPATIBLE_FILE);
        return INDIGO_ERROR_INCOMPATIBLE_FILE;
    }

    fread(settings, 1, sizeof(PSW_HASH_SETTINGS), fp);
    fclose(fp);
    if (settings->mem_cost < 13) {
        log_error("saved memory cost bellow minimum requirements %d < 13| return %d",
            settings->mem_cost, INDIGO_ERROR_INCOMPATIBLE_FILE);
        return INDIGO_ERROR_INCOMPATIBLE_FILE;
    }
    if (settings->mem_cost > 30) {
        log_error("saved memory cost above maximum requirements %d > 30| return %d",
            settings->mem_cost, INDIGO_ERROR_INCOMPATIBLE_FILE);
        return INDIGO_ERROR_INCOMPATIBLE_FILE;
    }
    if (settings->time_cost < crypto_pwhash_OPSLIMIT_MIN) {
        log_error("saved time cost bellow minimum requirements %d < %d| return %d",
            settings->time_cost, crypto_pwhash_OPSLIMIT_MIN, INDIGO_ERROR_INCOMPATIBLE_FILE);
        return INDIGO_ERROR_INCOMPATIBLE_FILE;
    }
    // if (settings->time_cost > crypto_pwhash_OPSLIMIT_MAX) {return
    // INDIGO_ERROR_INCOMPATIBLE_FILE;}
    return 0;
}

int key_derivation_settings_exist()
{
    char file_name[48] = INDIGO_PSW_DIR;
    strcat(file_name, "/");
    strcat(file_name, INDIGO_PSW_HASH_SETTINGS_FILE);

    if (access(file_name, F_OK) == 0)
        return 1;
    return 0;
}

int save_password_hash(const char *password, const uint64_t psw_len)
{
    unsigned char mem_cost;
    unsigned char time_cost;
    PSW_HASH_SETTINGS psw_settings;
    FILE *fp = NULL;
    char *psw_hash = NULL;
    char *file_name = NULL;
    int ret;
    char *init_cwd;
    char xpath[PATH_MAX];

    if (password == NULL || psw_len == 0) {
        log_error("null password or 0 password length | return %d", INDIGO_ERROR_INVALID_PARAM);
        return INDIGO_ERROR_INVALID_PARAM;
    }

    psw_hash = (char *)malloc(crypto_pwhash_STRBYTES + 1);
    if (psw_hash == NULL) {
        log_error("malloc failed allocating %lld bytes for password hash | return %d",
            crypto_pwhash_STRBYTES + 1, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    ret = load_key_derivation_settings(&psw_settings);
    if (ret != INDIGO_SUCCESS) {
        free(psw_hash);
        // possible file changed to incompatible values
        log_error("load_key_derivation_settings() failed | return %d", ret);
        return ret;
    }

    mem_cost = psw_settings.mem_cost;
    time_cost = psw_settings.time_cost;

    if (psw_len <= crypto_pwhash_PASSWD_MIN || psw_len >= crypto_pwhash_PASSWD_MAX) {
        free(psw_hash);
        log_error("password length (%d) not in valid range [%d,%d] | return %d",
            psw_len,crypto_pwhash_PASSWD_MIN, crypto_pwhash_PASSWD_MAX, INDIGO_ERROR_INVALID_PARAM );
        return INDIGO_ERROR_INVALID_PARAM;
    }

    ret = crypto_pwhash_str(psw_hash, password, psw_len, time_cost, 1 << mem_cost);

    if (ret == -1) {
        free(psw_hash);
        log_error("crypto_pwhash_str() failed | return %d", INDIGO_ERROR_SODIUM_ERROR);
        return INDIGO_ERROR_SODIUM_ERROR;
    }

    file_name = malloc(strlen(INDIGO_PSW_DIR) + strlen(INDIGO_PSW_HASH_FILE_NAME) + 2);
    if (file_name == NULL) {
        free(psw_hash);
        log_error("malloc failed allocating %lld bytes for password hash file name | return %d",
            strlen(INDIGO_PSW_DIR) + strlen(INDIGO_PSW_HASH_FILE_NAME) + 2,  INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    strcpy(file_name, INDIGO_PSW_DIR);
    strcat(file_name, "/");
    strcat(file_name, INDIGO_PSW_HASH_FILE_NAME);

    init_cwd = g_get_current_dir();
    if (get_source_dir(xpath)) {
        free(psw_hash);
        free(file_name);
        log_error("g_get_current_dir() failed possibly not enough memory | return %d",
            INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    chdir(xpath);

    g_mkdir_with_parents(INDIGO_PSW_DIR, 0755);

    fp = fopen(file_name, "w");
    if (fp == NULL) {
        chdir(init_cwd);
        g_free(init_cwd);
        free(psw_hash);
        free(file_name);
        log_error("failed opening file %s | return %d | errno %d", file_name, INDIGO_ERROR_FILE_NOT_FOUND, errno);
        return INDIGO_ERROR_FILE_NOT_FOUND; // todo check errno
    }

    fprintf(fp, "%s", psw_hash);

    chdir(init_cwd);
    g_free(init_cwd);
    free(file_name);
    fclose(fp);
    free(psw_hash);
    return INDIGO_SUCCESS;
}

int load_password_hash(char **hash)
{
    char *file_name = NULL;
    char *psw_hash = NULL;
    size_t hash_len = 0;
    FILE *fp = NULL;

    file_name = malloc(strlen(INDIGO_PSW_DIR) + strlen(INDIGO_PSW_HASH_FILE_NAME) + 2);
    if (file_name == NULL) {
        *hash = NULL;
        log_error("malloc failed allocating %lld bytes for password hash file name | return %d ",
            strlen(INDIGO_PSW_DIR) + strlen(INDIGO_PSW_HASH_FILE_NAME) + 2,  INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR );
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    strcpy(file_name, INDIGO_PSW_DIR"/"INDIGO_PSW_HASH_FILE_NAME);

    fp = fopen(file_name, "r");
    if (fp == NULL) {
        free(file_name);
        *hash = NULL;
        log_error("failed opening file %s | return %d | errno %d", file_name, INDIGO_ERROR_FILE_NOT_FOUND, errno);
        return INDIGO_ERROR_FILE_NOT_FOUND; // todo check errno
    }

    fseek(fp, 0, SEEK_END);
    hash_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (hash_len > crypto_pwhash_STRBYTES + 1) {
        printf("psw_hash incompatible length");
        fflush(stdout);
        free(psw_hash);
        free(file_name);
        fclose(fp);
        *hash = NULL;
        log_error("password hash has incompatible length %d while max length %d | return %d",
            hash_len, crypto_pwhash_STRBYTES ,INDIGO_ERROR_INCOMPATIBLE_FILE);
        return INDIGO_ERROR_INCOMPATIBLE_FILE;
    }

    psw_hash = (char *)malloc(crypto_pwhash_STRBYTES + 1);
    if (psw_hash == NULL) {
        free(psw_hash);
        fclose(fp);
        free(file_name);
        *hash = NULL;
        log_error("malloc failed allocating %lld bytes for password hash | return %d",
            crypto_pwhash_STRBYTES + 1, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    fread(psw_hash, 1, crypto_pwhash_STRBYTES, fp);
    *hash = psw_hash;

    free(file_name);
    fclose(fp);
    return INDIGO_SUCCESS;
}

// this function returns 0 on success, 1 on invalid signature and -1 on invalid
// input
int cmp_password_hash(const char *psw, const uint64_t psw_len)
{
    char *stored_hash = NULL;
    int ret = 0;

    if (psw == NULL || psw_len == 0) {
        return -1;
    }

    ret = load_password_hash(&stored_hash);
    if (ret != 0) {
        log_error("load_password_hash() failed | return -1");
        return -1;
    }

    ret = crypto_pwhash_str_verify(stored_hash, psw, psw_len);

    if (ret != 0) {
        free(stored_hash);
        log_info("incorrect password or crypto_pwhash_str_verify() fail");
        return 1;
    }

    free(stored_hash);
    return 0;
}

int password_hash_exists()
{
    char file_name[32] = INDIGO_PSW_DIR;
    strcat(file_name, "/");
    strcat(file_name, INDIGO_PSW_HASH_FILE_NAME);
    // returns 0 on success
    if (access(file_name, F_OK) == 0)
        return 1;
    return 0;
}

int create_signing_key_pair(void *master_key)
{
    signing_key_pair_t key_pair;
    unsigned char *cipher;
    unsigned char *nonce;
    char *file_name;
    FILE *fp;
    char *init_cwd;
    char xpath[PATH_MAX];
    int ret;

    if (master_key == NULL) {
        log_error("master key is null | return 1");
        return 1;
    }

    cipher = (unsigned char *)malloc(crypto_secretbox_MACBYTES + sizeof(signing_key_pair_t));
    if (cipher == NULL) {
        log_error("malloc failed allocating %lld bytes for generated key ciphertext | return %d",
            crypto_secretbox_MACBYTES + sizeof(signing_key_pair_t), INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    nonce = (unsigned char *)malloc(crypto_secretbox_NONCEBYTES);
    if (!nonce) {
        free(cipher);
        log_error("malloc failed allocating %lld bytes for generated key nonce | return %d",
            crypto_secretbox_NONCEBYTES, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    if (crypto_sign_keypair(key_pair.public, key_pair.secret) != 0) {
        free(nonce);
        free(cipher);
        log_error("crypto_sign_keypair() failed generating keys | retunr %d", INDIGO_ERROR_SODIUM_ERROR);
        return INDIGO_ERROR_SODIUM_ERROR;
    }

    ret = crypto_secretbox_easy(cipher, (unsigned char *)(&key_pair), sizeof(signing_key_pair_t), nonce, master_key);

    if (ret != 0) {
        free(cipher);
        free(nonce);
        log_error("crypto_secretbox_easy() failed encrypting generated key pair | return" ,INDIGO_ERROR_SODIUM_ERROR);
        return INDIGO_ERROR_SODIUM_ERROR;
    }

    file_name = malloc(strlen(INDIGO_KEY_DIR) + strlen(INDIGO_SIGN_KEY_FILE_NAME) + 2);
    if (file_name == NULL) {
        free(cipher);
        free(nonce);
        log_error("malloc failed allocating %lld bytes for signing keypair file name | return %d",
            strlen(INDIGO_KEY_DIR) + strlen(INDIGO_SIGN_KEY_FILE_NAME) + 2, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    init_cwd = g_get_current_dir();
    ret = get_source_dir(xpath);
    if (ret) {
        free(cipher);
        free(nonce);
        free(file_name);
        log_error("get_source_dir() failed | return %d", INDIGO_ERROR);
        return INDIGO_ERROR;
    }

    g_mkdir_with_parents(INDIGO_KEY_DIR, 0755);

    strcpy(file_name, INDIGO_KEY_DIR);
    strcat(file_name, "/");
    strcat(file_name, INDIGO_SIGN_KEY_FILE_NAME);

    fp = fopen(file_name, "wb");
    if (fp == NULL) {
        chdir(init_cwd);
        g_free(init_cwd);
        free(file_name);
        free(cipher);
        free(nonce);
        log_error("failed opening file %s | return %d | errno %d", file_name, INDIGO_ERROR_FILE_NOT_FOUND, errno);
        return INDIGO_ERROR_FILE_NOT_FOUND;
    }

    fwrite(nonce, 1, crypto_secretbox_NONCEBYTES, fp);
    fwrite(cipher, 1, crypto_secretbox_MACBYTES + sizeof(signing_key_pair_t), fp);

    sodium_memzero(&key_pair, sizeof(key_pair));

    chdir(init_cwd);
    g_free(init_cwd);
    fclose(fp);
    free(file_name);
    free(cipher);
    free(nonce);
    return INDIGO_SUCCESS;
}

int load_signing_key_pair(signing_key_pair_t *key_pair, const unsigned char *master_key)
{
    FILE *fp;
    char *file_name = NULL;
    uint32_t file_len = 0;
    unsigned char *cipher = NULL;
    unsigned char *nonce = NULL;
    int ret = 0;

    file_name = malloc(strlen(INDIGO_KEY_DIR) + strlen(INDIGO_SIGN_KEY_FILE_NAME) + 2);
    if (file_name == NULL) {
        log_error("malloc failed allocating %lld bytes for signing keypair file name | return %d",
            strlen(INDIGO_KEY_DIR) + strlen(INDIGO_SIGN_KEY_FILE_NAME) + 2, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    strcpy(file_name, INDIGO_KEY_DIR);
    strcat(file_name, "/");
    strcat(file_name, INDIGO_SIGN_KEY_FILE_NAME);

    fp = fopen(file_name, "rb");
    if (fp == NULL) {
        free(file_name);
        log_error("failed opening file %s | return %d | errno %d", file_name, INDIGO_ERROR_FILE_NOT_FOUND, errno);
        return INDIGO_ERROR_FILE_NOT_FOUND;
    }
    free(file_name);

    fseek(fp, 0, SEEK_END);
    file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_len != crypto_secretbox_MACBYTES + sizeof(signing_key_pair_t) + crypto_secretbox_NONCEBYTES) {
        fclose(fp);
        log_error("sign keypair file length found incompatible %d where is should be %d | return $d",
            file_len, crypto_secretbox_MACBYTES + sizeof(signing_key_pair_t) + crypto_secretbox_NONCEBYTES,
            INDIGO_ERROR_INCOMPATIBLE_FILE);
        return INDIGO_ERROR_INCOMPATIBLE_FILE;
    }

    cipher = malloc(crypto_secretbox_MACBYTES + sizeof(signing_key_pair_t));
    if (cipher == NULL) {
        fclose(fp);
        log_error("malloc failed allocating %lld bytes for keypair ciphertext | return %d",
            crypto_secretbox_MACBYTES + sizeof(signing_key_pair_t), INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    nonce = malloc(crypto_secretbox_NONCEBYTES);
    if (nonce == NULL) {
        fclose(fp);
        free(cipher);
        log_error("malloc failed allocating %lld bytes for keypair nonce | return %d",
            crypto_secretbox_NONCEBYTES, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    fread(nonce, 1, crypto_secretbox_NONCEBYTES, fp);
    fread(cipher, 1, crypto_secretbox_MACBYTES + sizeof(signing_key_pair_t), fp);

    ret = crypto_secretbox_open_easy((unsigned char *)key_pair, cipher,
                                     crypto_secretbox_MACBYTES + sizeof(signing_key_pair_t), nonce, master_key);

    if (ret != 0) {
        fclose(fp);
        free(nonce);
        free(cipher);
        log_error("crypto_secretbox_open_easy() failed to decrypt the signing keys | return %d",
            INDIGO_ERROR_FALSE_KEY);
        return INDIGO_ERROR_FALSE_KEY;
    }

    free(cipher);
    free(nonce);
    fclose(fp);
    return INDIGO_SUCCESS;
}

int sign_buffer(const signing_key_pair_t *key_pair, const unsigned char *buffer, uint64_t buffer_len,
                unsigned char *signed_buffer, uint64_t *signed_len)
{
    return crypto_sign(signed_buffer, (unsigned long long *)signed_len, buffer, buffer_len, key_pair->secret);
}

int signing_key_pair_exists()
{
    char filename[32];
    strcpy(filename, INDIGO_KEY_DIR);
    strcat(filename, INDIGO_SIGN_KEY_FILE_NAME);

    if (access(filename, F_OK)) {
        return 0;
    }
    return 1;
}

int encrypt_packet(packet_t *packet, unsigned char tk[crypto_kx_SESSIONKEYBYTES],
                   const unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
{

    int ret;
    unsigned char ciphertext[PAC_ENCRYPT_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES] = {0};

    if (!packet || !tk) {
        return INDIGO_ERROR_INVALID_PARAM;
    }

    if (!nonce) {
        randombytes_buf(packet->nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    }
    else {
        memcpy(packet->nonce, nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    }

    packet->zero = 0;

    ret = crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, NULL, (unsigned char *)&(packet->zero),
                                                     PAC_ENCRYPT_BYTES, (unsigned char *)packet, PAC_ENCRYPT_OFFSET,
                                                     NULL, packet->nonce, tk);
    if (ret != 0) {
        log_error("crypto_aead_xchacha20poly1305_ietf_encryp() failed | return %d",INDIGO_ERROR_INVALID_PARAM);
        return INDIGO_ERROR_INVALID_PARAM;
    }
    sodium_memzero(&(packet->zero), PAC_ENCRYPT_BYTES);
    memcpy(&(packet->zero), ciphertext, PAC_ENCRYPT_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES);

    return INDIGO_SUCCESS;
}

int decrypt_packet(packet_t *packet, unsigned char rk[crypto_kx_SESSIONKEYBYTES])
{
    int ret;
    unsigned long long decrypted_len;
    if (!packet || !rk)
        return INDIGO_ERROR_INVALID_PARAM;

    ret = crypto_aead_xchacha20poly1305_ietf_decrypt((unsigned char *)&(packet->zero), &decrypted_len, NULL,
                                                     (unsigned char *)&(packet->zero),
                                                     PAC_ENCRYPT_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES,
                                                     (unsigned char *)packet, PAC_ENCRYPT_OFFSET, packet->nonce, rk);

    if (ret == 0) {
        // zero out the parts of the packet that is not data
        sodium_memzero(((unsigned char *)&(packet->zero)) + decrypted_len,
                       PAC_ENCRYPT_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES - decrypted_len);
        return INDIGO_SUCCESS;
    }
    if (ret == -1) {
        log_warn("attempt to decrypt invalid packet | return %d ",INDIGO_ERROR_INVALID_PACKET);
        return INDIGO_ERROR_INVALID_PACKET;
    }
    log_error("unknown error in decrypt packet | return %d", INDIGO_ERROR);
    return INDIGO_ERROR;
}

int nonce_increment(unsigned char *nonce, size_t nonce_len, uint64_t increment)
{
    unsigned char *incr_bytes;

    incr_bytes = calloc(1, nonce_len);
    if (!incr_bytes) {
        log_error("calloc() failed allocating %d bytes used for temporary nonce buffer | return %d",
            nonce_len, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    for (int i = 0; i < CHAR_BIT; i++) {
        incr_bytes[i] = (increment >> (i << 3)) & 0xFF;
    }

    sodium_add(nonce, incr_bytes, nonce_len);
    free(incr_bytes);
    return INDIGO_SUCCESS;
}

int bypass_password(void **master_key) {
    int ret;
    char psw[] = "test";
    char *stored_hash;

    ret = load_password_hash(&stored_hash);
    if (ret != 0) {
        log_error("load_password_hash() failed | return -1");
        return -1;
    }

    ret = crypto_pwhash_str_verify(stored_hash, psw, 4);
    if (ret) {
        log_debug("couldn't verify password hash");
        return -1;
    }
    ret = derive_master_key(psw, 4, master_key);
    if (ret != 0) {
        log_error("[bypass_password] derive_master_key() failed | return %d", ret);
        return -1;
    }
    return 0;
}