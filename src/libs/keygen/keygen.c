//
// Created by Constantin on 14/08/2025.
//

#include "keygen.h"
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/encoder.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>

int derive_master_key(const char *psw, const uint32_t psw_len, void **master_key, uint32_t *key_len) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM *params = NULL;

    uint32_t iter = 1;
    uint32_t memcost = 1LL << 21;
    uint32_t lanes = 4;

    void *salt = NULL;
    uint32_t salt_len = 0;

    unsigned char *key = NULL;


    if (psw == NULL) return 1;
    if (psw_len == 0) return 1;
    if (load_psw_salt(&salt)) return 1;

    if (CRYPTO_secure_malloc_init(1LL<<7 , 0))goto cleanup; //128 bytes of memory

    *key_len = INDIGO_DEFAULT_MASTER_KEY_SIZE;
    key = OPENSSL_secure_malloc(*key_len);
    if (key == NULL) goto cleanup;

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if ((bld == NULL)
        || !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_PASSWORD, psw, psw_len)
        || !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SALT,salt , salt_len)
        || !OSSL_PARAM_BLD_push_uint32(bld, OSSL_KDF_PARAM_ARGON2_MEMCOST, memcost)
        || !OSSL_PARAM_BLD_push_uint32(bld, OSSL_KDF_PARAM_ARGON2_LANES, lanes)
        || !OSSL_PARAM_BLD_push_uint32(bld, OSSL_KDF_PARAM_ITER, iter)
        || !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_PROPERTIES, "fips=yes",9)) {
        goto cleanup;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) goto cleanup;
    OSSL_PARAM_BLD_free(bld);
    bld = NULL;

    if ((kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL)) == NULL)
        goto cleanup;
    if ((ctx = EVP_KDF_CTX_new(kdf)) == NULL)
        goto cleanup;
    if (EVP_KDF_derive(ctx, key, *key_len, params) != 1)
        goto cleanup;

    *master_key = key;

    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);
    OSSL_PARAM_free(params);
    free(salt);
    return 0;

    cleanup:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    free(salt);
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
        return 2;
    }

    fp_salt = fopen(file_name, "wb");
    if (fp_salt == NULL) {
        free(file_name);
        return 1;
    }

    salt = malloc(numBytes);
    if (salt == NULL) {
        free(file_name);
        fclose(fp_salt);
        return 1;
    }

    RAND_bytes(salt, numBytes);

    fwrite(salt, numBytes, 1, fp_salt);

    fclose(fp_salt);
    free(file_name);
    free(salt);
    return 0;
}

int load_psw_salt(unsigned char** salt) {
    char *file_name;
    FILE *fp_salt;

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
    *numBytes = ftell(fp_salt);
    fseek(fp_salt, 0, SEEK_SET);

    *salt = malloc(*numBytes);
    if (*salt == NULL) {
        free(file_name);
        fclose(fp_salt);
        return 1;
    }

    fread(*salt, *numBytes, 1, fp_salt);

    fclose(fp_salt);
    free(file_name);
    return 0;
}

int create_rsa_key_pair(const char *psw, const uint32_t psw_len, char overwrite) {
    void *master_key = NULL;
    uint32_t master_key_len;

    char *file_name = NULL;
    FILE *fp_rsa = NULL;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    EVP_CIPHER *cipher = NULL;

    unsigned char *rsa_der = NULL;
    size_t rsa_der_len = 0;

    unsigned char *iv[INDIGO_DEFAULT_IV_LEN];
    unsigned char *tag[INDIGO_DEFAULT_TAG_LEN];

    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;

    if (psw == NULL || psw_len == 0) return 1;

    file_name = malloc(strlen(INDIGO_KEY_DIR) + strlen("/rsa.dat") + 1);
    if (file_name == NULL) return 1;
    strcpy(file_name, INDIGO_KEY_DIR);
    strcat(file_name, "/rsa.dat");

    if ((overwrite == 0) && access(file_name,F_OK)) {
        free(file_name);
        return 2;
    }

    if (derive_master_key(psw,psw_len,&master_key,&master_key_len)) goto cleanup;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pctx == NULL) goto cleanup;

    if ((EVP_PKEY_keygen_init(pctx) != 1) || (EVP_PKEY_generate(pctx,&pkey) != 1))goto cleanup;

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey,EVP_PKEY_KEYPAIR,"DER",NULL,NULL);
    if (ectx == NULL) goto cleanup;

    if (OSSL_ENCODER_to_data(ectx,&rsa_der,&rsa_der_len) != 1) goto cleanup;

    OSSL_ENCODER_CTX_free(ectx);
    ectx = NULL;


    cipher = EVP_CIPHER_fetch(NULL,"AES-256-GCM",NULL);
    if (cipher == NULL) goto cleanup;

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL) goto cleanup;

    if (EVP_EncryptInit_ex2(cctx,cipher,NULL,NULL,NULL) != 1 ) goto cleanup;

    if (!EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, INDIGO_DEFAULT_IV_LEN, NULL))goto cleanup;

    if ((RAND_bytes(iv,INDIGO_DEFAULT_IV_LEN) != 1)
        || (EVP_EncryptInit_ex2(cctx,NULL,master_key,iv,NULL) != 1) ) goto cleanup;

    ciphertext_len = (int)rsa_der_len;
    ciphertext = malloc(ciphertext_len);
    if (ciphertext == NULL) goto cleanup;

    if (EVP_EncryptUpdate(cctx,ciphertext,&ciphertext_len,rsa_der,rsa_der_len) != 1)goto cleanup;

    if (EVP_EncryptFinal_ex(cctx,ciphertext + ciphertext_len,&ciphertext_len) != 1) goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto cleanup;

    fp_rsa = fopen(file_name, "wb");
    if (fp_rsa == NULL) goto cleanup;

    fwrite(iv, INDIGO_DEFAULT_IV_LEN, 1, fp_rsa);
    fwrite(ciphertext, ciphertext_len, 1, fp_rsa);
    fwrite(tag, INDIGO_DEFAULT_TAG_LEN, 1, fp_rsa);
    fclose(fp_rsa);


    free(ciphertext);
    free(file_name);
    return 0;
    cleanup:
    return 1;
}

int delete_rsa_key_pair() {
    return 0;
}