//
// Created by Constantin on 10/08/2025.
//

#include "crypto_utils.h"

#include <math.h>
#include <unistd.h>
#include <sodium.h>

#ifdef _WIN32
#include <sysinfoapi.h>
#include <profileapi.h>
#endif

struct PSW_HASH_SETTINGS {
    unsigned char mem_cost;
    unsigned char time_cost;
};

struct SIGNING_KEY_PAIR {
    unsigned char public[crypto_sign_PUBLICKEYBYTES];
    unsigned char secret[crypto_sign_SECRETKEYBYTES];
};

int derive_master_key(const char* psw, const uint64_t psw_len, void** master_key) {
    uint64_t mem_cost = crypto_pwhash_MEMLIMIT_MIN;
    unsigned char time_cost = crypto_pwhash_OPSLIMIT_MIN;
    unsigned char *out_key = NULL ;
    unsigned char *salt = NULL;
    PSW_HASH_SETTINGS psw_settings;
    int ret;


    if (psw == NULL || master_key == NULL) return 2;

    ret = load_key_derivation_settings(&psw_settings);
    if (ret != 0) {
        return 3;//possible file changed to incompatible values
    }

    mem_cost = psw_settings.mem_cost;
    time_cost = psw_settings.time_cost;

    ret = load_psw_salt(&salt);
    if (ret == -3) {
        return 3;//possible file changed to incompatible values
    }
    if (ret  == INDIGO_FILE_NOT_FOUND) {
        return INDIGO_FILE_NOT_FOUND;
    }

    if (psw_len <= crypto_pwhash_PASSWD_MIN || psw_len >= crypto_pwhash_PASSWD_MAX) goto cleanup;

    out_key = sodium_malloc(crypto_secretbox_KEYBYTES);
    if (!out_key) goto cleanup;

    ret = crypto_pwhash(out_key,
        crypto_secretbox_KEYBYTES,
        psw,
        psw_len,
        salt,
        time_cost,
        1<<mem_cost,
        crypto_pwhash_ALG_ARGON2ID13);
    if (ret == -1) goto cleanup;

    *master_key = out_key;

    free(salt);
    return 0;

    cleanup:
    sodium_free(out_key);
    free(salt);
    *master_key = NULL;
    return 1;
}

int create_psw_salt(char overwrite) {
    void *salt;
    char *file_name;
    FILE *fp_salt;

    file_name = malloc(strlen(INDIGO_PSW_DIR) + strlen("/salt.dat") + 1);
    if (file_name == NULL) return 1;
    strcpy(file_name, INDIGO_PSW_DIR);
    strcat(file_name, "/salt.dat");

    if ((overwrite == 0) && access(file_name,F_OK)) {
        free(file_name);
        return INDIGO_FILE_NOT_FOUND;
    }

    fp_salt = fopen(file_name, "wb");
    if (fp_salt == NULL) {
        free(file_name);
        return 1;
    }

    salt = malloc(crypto_pwhash_SALTBYTES);
    if (salt == NULL) {
        free(file_name);
        fclose(fp_salt);
        return 1;
    }

    randombytes_buf(salt, crypto_pwhash_SALTBYTES);

    fwrite(salt, crypto_pwhash_SALTBYTES, 1, fp_salt);

    fclose(fp_salt);
    free(file_name);
    free(salt);
    return 0;
}

int load_psw_salt(unsigned char **salt) {
    char *file_name;
    FILE *fp_salt;
    uint32_t salt_len;

    if (salt == NULL) return 1;

    file_name = malloc(strlen(INDIGO_PSW_DIR) + strlen("/salt.dat") + 1);
    if (file_name == NULL) return 1;
    strcpy(file_name, INDIGO_PSW_DIR);
    strcat(file_name, "/salt.dat");

    if (!access(file_name, F_OK)) {
        free(file_name);
        return 2;
    }

    fp_salt = fopen(file_name, "rb");
    if (fp_salt == NULL) {
        free(file_name);
        return 1;
    }


    fseek(fp_salt, 0, SEEK_END);
    salt_len = ftell(fp_salt);
    fseek(fp_salt, 0, SEEK_SET);


    if (salt_len != crypto_pwhash_SALTBYTES) {
        free(file_name);
        fclose(fp_salt);
        return -3;
    }


    *salt = malloc(salt_len);
    if (*salt == NULL) {
        free(file_name);
        fclose(fp_salt);
        return 1;
    }

    fread(*salt, salt_len, 1, fp_salt);

    fclose(fp_salt);
    free(file_name);
    return 0;
}

int create_key_derivation_settings() {
    LARGE_INTEGER freq, start_time, end_time;
    LARGE_INTEGER elapsed_time;
    double elapsed_usec;
    double mean_elapsed = 0;
    int i, ret;

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char out_key[crypto_secretbox_KEYBYTES];
    unsigned char psw[15];

    uint64_t time_cost = 3;
    uint64_t mem_cost;
    uint8_t max_mem_cost;

    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
    randombytes_buf(psw, 15);

    MEMORYSTATUSEX ram;
    size_t total_mem;

    FILE *fp;

    PSW_HASH_SETTINGS settings;


    GlobalMemoryStatusEx(&ram);
    total_mem = ram.ullTotalPhys;
    max_mem_cost = floor(log2((double)total_mem/4));
    if (max_mem_cost > 30) max_mem_cost = 30;
    if (max_mem_cost < 13) return -2;
    mem_cost = max_mem_cost;


    for (int j = 0; j < 5; j++) {
        mean_elapsed = 0;
        for (i = 0; i < 3; i++) {
            QueryPerformanceFrequency(&freq); //sets the tick frequency
            QueryPerformanceCounter(&start_time); //sets the tick count at the start

            ret = crypto_pwhash(out_key,
            crypto_secretbox_KEYBYTES,
            psw,
            15,
            salt,
            time_cost,
            1<<mem_cost,
            crypto_pwhash_ALG_ARGON2ID13);

            QueryPerformanceCounter(&end_time); //sets the tick count at the end
            if (ret == -1) return -2;

            elapsed_time.QuadPart = end_time.QuadPart - start_time.QuadPart;
            elapsed_usec = (double)elapsed_time.QuadPart * 1000000;
            elapsed_usec /= (double)freq.QuadPart;
            mean_elapsed += elapsed_usec;
        }
        mean_elapsed /= i*1000000;
        if (mean_elapsed < INDIGO_PSW_HASH_TIMELIMIT_UPPER && mean_elapsed > INDIGO_PSW_HASH_TIMELIMIT_LOWER) break;
        if (mean_elapsed < INDIGO_PSW_HASH_TIMELIMIT_LOWER) {
            if (mem_cost < max_mem_cost) {
                mem_cost++;
            }
            else {
                time_cost++;
            }
        }
        if (mean_elapsed > INDIGO_PSW_HASH_TIMELIMIT_UPPER) {
            if (mem_cost > 13) mem_cost--;
            else if (time_cost > 1) time_cost--;
            else break;
        }
    }
    settings.mem_cost = (char)mem_cost;
    settings.time_cost = (char)time_cost;

    printf("debug: %lld %lld %lf \n",mem_cost,time_cost, mean_elapsed);
    fp = fopen(INDIGO_PSW_HASH_SETTINGS_FILE, "wb");
    fwrite(&settings, sizeof(PSW_HASH_SETTINGS), 1, fp);

    fclose(fp);
    return 0;
}

int save_key_derivation_settings(uint8_t mem_cost, uint8_t time_cost) {
    PSW_HASH_SETTINGS settings;
    settings.mem_cost = mem_cost;
    settings.time_cost = time_cost;
    FILE *fp = fopen(INDIGO_PSW_HASH_SETTINGS_FILE, "wb");
    if (fp == NULL) return 1;
    fwrite(&settings, sizeof(PSW_HASH_SETTINGS), 1, fp);

    fclose(fp);
    return 0;
}

int load_key_derivation_settings(PSW_HASH_SETTINGS *settings) {
    FILE *fp;
    size_t len;

    fp = fopen(INDIGO_PSW_HASH_SETTINGS_FILE, "rb");
    if (fp == NULL) return -1;

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len != sizeof(PSW_HASH_SETTINGS)) {
        fclose(fp);
        return -3;
    }

    fread(settings, 1, sizeof(PSW_HASH_SETTINGS), fp);
    fclose(fp);
    if (settings->mem_cost < 13) return -3;
    if (settings->mem_cost > 30) return -3;
    if (settings->time_cost < crypto_pwhash_OPSLIMIT_MIN) return -3;
    if (settings->time_cost > crypto_pwhash_OPSLIMIT_MAX) return -3;
    return 0;
}

int save_password_hash(const char* password, const uint64_t psw_len) {
    unsigned char mem_cost;
    unsigned char time_cost;
    PSW_HASH_SETTINGS psw_settings;
    FILE *fp = NULL;
    char *psw_hash = NULL, *file_name = NULL;
    int ret;


    if (password == NULL || psw_len == 0) return 2;

    psw_hash = (char *)malloc(crypto_pwhash_STRBYTES +1);
    if (psw_hash == NULL) return 1;

    ret = load_key_derivation_settings(&psw_settings);
    if (ret != 0) {
        return 3;//possible file changed to incompatible values
    }

    mem_cost = psw_settings.mem_cost;
    time_cost = psw_settings.time_cost;


    if (psw_len <= crypto_pwhash_PASSWD_MIN || psw_len >= crypto_pwhash_PASSWD_MAX) {
        free(psw_hash);
        return 1;
    }


    ret = crypto_pwhash_str(psw_hash,
        password,
        psw_len,
        time_cost,
        1<<mem_cost);
    if (ret == -1) {
        free(psw_hash);
        return 1;
    }

    file_name = malloc(strlen(INDIGO_PSW_DIR) + strlen(INDIGO_PSW_HASH_FILE_NAME) + 1);
    if (file_name == NULL) return 1;
    strcpy(file_name, INDIGO_PSW_DIR);
    strcat(file_name, INDIGO_PSW_HASH_FILE_NAME);

    fp = fopen(file_name, "w");
    if (fp == NULL) {
        free(psw_hash);
        free(file_name);
        return -1;
    }

    fprintf(fp, "%s", psw_hash);

    free(file_name);
    fclose(fp);
    free(psw_hash);
    return 0;
}

int load_password_hash(char** hash) {
    char *file_name = NULL;
    char *psw_hash = NULL;
    int hash_len = 0;
    FILE *fp = NULL;


    file_name = malloc(strlen(INDIGO_PSW_DIR) + strlen(INDIGO_PSW_HASH_FILE_NAME) + 1);
    if (file_name == NULL) {
        *hash = NULL;
        return 1;
    }
    strcpy(file_name, INDIGO_PSW_DIR);
    strcat(file_name, INDIGO_PSW_HASH_FILE_NAME);

    fp = fopen(file_name, "r");
    if (fp == NULL) {
        free(file_name);
        *hash = NULL;
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    hash_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);


    if (hash_len != crypto_pwhash_STRBYTES +1) {
        printf("psw_hash incompatible lenght");
        fflush(stdout);
        free(psw_hash);
        fclose(fp);
        *hash = NULL;
        return 1;
    }

    psw_hash = (char *)malloc(crypto_pwhash_STRBYTES + 1);
    if (psw_hash == NULL) {
        free(psw_hash);
        fclose(fp);
        *hash = NULL;
        return 1;
    }

    fread(psw_hash, 1, crypto_pwhash_STRBYTES, fp);
    *hash = psw_hash;

    free(file_name);
    fclose(fp);
    return 0;
}

int cmp_password_hash(char* psw, uint64_t psw_len) {
    char *stored_hash = NULL;
    int ret = 0;

    if (psw == NULL || psw_len == 0) return 1;

    ret = load_password_hash(&stored_hash);
    if (ret != 0) {
        return -1;
    }

    ret = crypto_pwhash_str_verify(stored_hash, psw, psw_len);

    if (ret != 0) {
        free(stored_hash);
        return 1;
    }

    free(stored_hash);
    return 0;

}

int create_signing_key_pair(const unsigned char* const master_key) {
    SIGNING_KEY_PAIR key_pair;
    unsigned char *cipher;
    unsigned char *nonce;
    char *file_name;
    FILE *fp;
    int ret;


    cipher = (unsigned char *)malloc(crypto_secretbox_MACBYTES + sizeof(SIGNING_KEY_PAIR));
    if (cipher == NULL) return 1;

    nonce = (unsigned char *)malloc(crypto_secretbox_NONCEBYTES);

    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    if (crypto_sign_keypair(key_pair.public, key_pair.secret) != 0) {
        free(nonce);
        free(cipher);
        return 1;
    }

    ret = crypto_secretbox_easy(cipher, (unsigned char *)(&key_pair),sizeof(SIGNING_KEY_PAIR),nonce,master_key);

    if (ret != 0) {
        free(cipher);
        free(nonce);
        return -1;
    }

    file_name = malloc(strlen(INDIGO_KEY_DIR) + strlen(INDIGO_SIGN_KEY_FILE_NAME) + 1);
    if (file_name == NULL) return 1;
    strcpy(file_name, INDIGO_PSW_DIR);
    strcat(file_name, INDIGO_SIGN_KEY_FILE_NAME);

    fp = fopen(file_name, "wb");
    if (fp == NULL) {
        free(file_name);
        free(cipher);
        free(nonce);
        return 1;
    }

    fwrite(nonce, 1, crypto_secretbox_NONCEBYTES, fp);
    fwrite(cipher, 1, crypto_secretbox_MACBYTES + sizeof(SIGNING_KEY_PAIR), fp);

    fclose(fp);
    free(file_name);
    free(cipher);
    free(nonce);
    return 0;
}

int load_signing_key_pair(SIGNING_KEY_PAIR *key_pair,const unsigned char* master_key) {
    FILE *fp;
    char *file_name = NULL;
    uint32_t file_len = 0;
    unsigned char *cipher = NULL;
    unsigned char *nonce = NULL;
    int ret = 0;

    file_name = malloc(strlen(INDIGO_KEY_DIR) + strlen(INDIGO_SIGN_KEY_FILE_NAME) + 1);
    if (file_name == NULL) return 1;
    strcpy(file_name, INDIGO_PSW_DIR);
    strcat(file_name, INDIGO_SIGN_KEY_FILE_NAME);

    fp = fopen(file_name, "rb");
    if (fp == NULL) {
        free(file_name);
        return 1;
    }
    free(file_name);

    fseek(fp, 0, SEEK_END);
    file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_len != crypto_secretbox_KEYBYTES + sizeof(SIGNING_KEY_PAIR) + crypto_secretbox_NONCEBYTES) {
        fclose(fp);
        return 2;
    }

    cipher = (unsigned char *)malloc(crypto_secretbox_KEYBYTES + sizeof(SIGNING_KEY_PAIR));
    if (cipher == NULL) {
        fclose(fp);
        return 1;
    }
    nonce = (unsigned char *)malloc(crypto_secretbox_NONCEBYTES);
    if (nonce == NULL) {
        fclose(fp);
        free(cipher);
        return 1;
    }

    fread(nonce, 1, crypto_secretbox_NONCEBYTES, fp);
    fread(cipher, 1, crypto_secretbox_KEYBYTES + sizeof(SIGNING_KEY_PAIR), fp);

    ret =  crypto_secretbox_open_easy((unsigned char *)key_pair,
        cipher,
        crypto_secretbox_KEYBYTES + sizeof(SIGNING_KEY_PAIR) ,
        nonce,
        master_key);

    if (ret != 0) {
        fclose(fp);
        free(nonce);
        free(cipher);
        return -1;
    }

    free(cipher);
    free(nonce);
    fclose(fp);
    return 0;
}

