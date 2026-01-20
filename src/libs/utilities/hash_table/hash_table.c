//
// Created by Constantin on 06/01/2026.
//
#include "hash_table.h"

#include <stdlib.h>
#include <string.h>


struct hash_table_priv {
    hashFunction hash;          //kinda useless, we always use MurMurHash anyway
    cmpFunction cmp;
    unsigned char *table;                //the array of the hash table
    size_t data_size;           //the number of bytes of the data part of the bucket
    size_t bucket_count;        //the total number of buckets on the first level
    uint32_t key_length;        //the number of bytes of the key part of the buckets
    uint8_t hash_bit_length;    //the nuber of bits we use out of the 32 we get from the hashfunction
    unsigned char zero[3];
};


hash_table_t *new_hash_table(size_t data_size, size_t key_length, size_t init_size, cmpFunction cmp) {
    hash_table_priv *priv;
    hash_table_t *ht;
    if (cmp == NULL || data_size == 0) {
        return NULL;
    }
    ht = (hash_table_t *)malloc(sizeof(hash_table_t));
    if (ht == NULL) return NULL;
    priv= malloc(sizeof(struct hash_table_priv));
    if (ht->private == NULL) {
        free(ht);
        return NULL;
    }
    ht->private = priv;

    priv->hash = MurMurHash;
    priv->cmp = cmp;
    priv->bucket_count = init_size ? init_size : 1;
    priv->hash_bit_length = sizeof(size_t) * 8 - __builtin_ctz(init_size * init_size - 1);
    priv->data_size = data_size;
    priv->key_length = key_length ? key_length : sizeof(uint32_t);
    priv->table = (unsigned char *)malloc((1<<priv->hash_bit_length) * (sizeof(void *) + priv->data_size + priv->key_length));
    if (priv->table == NULL) {
        free(priv);
        free(ht);
        return NULL;
    }
    ht->insert = hash_table_insert;
    ht->remove = hash_table_delete;
    ht->search = hash_table_search;
    return ht;
}
void delete_hash_table(hash_table_t *ht) {
    /*todo remove the linked list nodes*/
    free(ht->private->table);
    free(ht->private);
    free(ht);
}

int hash_table_insert(hash_table_t *ht, void *key, void *data){
    //the hash table should have a size of (at least) n^2 where n is the number of buckets
    size_t new_size, old_size;
    hash_table_priv *priv;
    int hash_code;
    unsigned char *bucket, *new_bucket, *new_table;

    if (!ht || !key || !data) {
        return 0;
    }
    priv = ht->private;

    new_size = (sizeof(size_t) * 8) - __builtin_clzll((priv->bucket_count+1) * (priv->bucket_count+1) - 1);
    old_size = priv->hash_bit_length;
    if (old_size >= new_size) {
        //we don't need to allocate more memory
        hash_code = priv->hash(key,priv->key_length);
        hash_code &= (1<<priv->hash_bit_length) - 1;
        bucket = priv->table + hash_code * (priv->data_size + priv->key_length + sizeof(void *));
        /*if the key is 0 then the bucket is empty and ready to use*/
        if (is_zero(bucket + sizeof(void *), priv->key_length)) {
            memcpy(bucket + sizeof(void *), key, priv->key_length);
            memcpy(bucket + sizeof(void *) + priv->key_length, data, priv->data_size);
        }
        else {
            new_bucket = malloc(priv->data_size + priv->key_length + sizeof(void *));
            if (!new_bucket) return 1;

            /*insert the bucket to the linked list*/
            memcpy(new_bucket, bucket,sizeof(void *));
            memcpy(bucket, &new_bucket, sizeof(void *));

            memcpy(new_bucket + sizeof(void *), key, priv->key_length);
            memcpy(new_bucket + sizeof(void *) + priv->key_length, data, priv->data_size);
        }
    }
    else {
        /*we need to resize the hash table (allocate a new table and move all the previous buckets to the new table)*/
        new_table = malloc((1<<new_size) * (sizeof(void *) + priv->key_length + priv->data_size));
        if (!new_table) return 1;
        priv->hash_bit_length += 1;
        for (size_t i = 0; i < old_size; i++) {
            bucket = priv->table + i * (sizeof(void*) + priv->key_length+priv->data_size);
            if (is_zero(bucket + sizeof(void *), priv->key_length)) continue;

            for (unsigned char * b = bucket; b != NULL; b = *(void**)b) {
                hash_code = priv->hash((char *)b + sizeof(void*),priv->key_length);
                hash_code &= (1<<priv->hash_bit_length) - 1;

                new_bucket = new_table + hash_code * (priv->data_size + priv->key_length + sizeof(void *));
                if (hash_table_bucket_insert(priv,new_bucket,b + sizeof(void *),b + sizeof(void *) + priv->key_length)){
                    free(new_table);
                    priv->hash_bit_length -= 1;
                    return 1;
                }
            }
        }

        free(priv->table);
        priv->table = new_table;

        /*the old table has been resized, now we insert the new element*/

        hash_code = priv->hash(key,priv->key_length);
        hash_code &= (1<<priv->hash_bit_length) - 1;
        bucket = priv->table + hash_code * (priv->data_size + priv->key_length + sizeof(void *));
        hash_table_bucket_insert(priv,bucket,key,data);
    }
    priv->bucket_count++;
    return 0;
}
void *hash_table_search(hash_table_t *ht, void *key) {
    int hash_code;
    unsigned char *bucket;
    hash_table_priv *priv;
    if (!ht || !key) {
        return NULL;
    }
    priv = ht->private;

    hash_code = priv->hash(key,priv->key_length);
    hash_code &= (1<<priv->hash_bit_length) - 1;
    bucket = priv->table + hash_code * (priv->data_size + priv->key_length + sizeof(void *));

    while (memcmp(key,bucket + sizeof(void *), priv->key_length) != 0) {
        bucket = *(void **)bucket;
        if (!bucket) return NULL;
    }
    return bucket + sizeof(void *) + priv->key_length;
}
int hash_table_delete(hash_table_t *ht, void *key) {
    int hash_code;
    unsigned char *bucket, *prev = NULL, *temp, *new_bucket, *new_table;
    size_t old_size, new_size;
    hash_table_priv *priv;
    if (!ht || !key) {
        return -1;
    }
    priv = ht->private;

    hash_code = priv->hash(key,priv->key_length);
    hash_code &= (1<<priv->hash_bit_length) - 1;
    bucket = priv->table + hash_code * (priv->data_size + priv->key_length + sizeof(void *));
    while (memcmp(key,bucket + sizeof(void *), priv->key_length) != 0) {
        prev = bucket;
        bucket = *(void **)bucket;
        if (!bucket) return 1;
    }
    if (!prev) {
        temp = *(void **)bucket;
        if (temp) {
            memcpy(bucket, temp, sizeof(void *) + priv->key_length + priv->data_size);
            free(temp);
        }
        else {
            memset(bucket, 0, sizeof(void *) + priv->key_length + priv->data_size);
        }
    }
    else {
        memcpy(prev, bucket, sizeof(void *));
        free(bucket);
    }

    old_size = priv->hash_bit_length;
    priv->bucket_count--;
    new_size = (sizeof(size_t) * 8) - __builtin_clzll(priv->bucket_count * priv->bucket_count - 1);

    if (new_size < old_size) {
        /*we need to resize the hash table (allocate a new table and move all the previous buckets to the new table)*/
        new_table = malloc((1<<new_size) * (sizeof(void *) + priv->key_length + priv->data_size));
        if (!new_table) return 1;
        priv->hash_bit_length += 1;
        for (size_t i = 0; i < old_size; i++) {
            bucket = priv->table + i * (sizeof(void*) + priv->key_length+priv->data_size);
            if (is_zero(bucket + sizeof(void *), priv->key_length)) continue;

            for (unsigned char * b = bucket; b != NULL; b = *(void**)b) {
                hash_code = priv->hash((char *)b + sizeof(void*),priv->key_length);
                hash_code &= (1<<priv->hash_bit_length) - 1;

                new_bucket = new_table + hash_code * (priv->data_size + priv->key_length + sizeof(void *));
                if (hash_table_bucket_insert(priv,new_bucket,b + sizeof(void *),b + sizeof(void *) + priv->key_length)){
                    free(new_table);
                    priv->hash_bit_length -= 1;
                    return 1;
                }
            }
        }

        free(priv->table);
        priv->table = new_table;
    }
    return 0;
}

int hash_table_bucket_insert(hash_table_priv *table, unsigned char *bucket, void *key, void *data) {
    unsigned char *new_bucket;

    if (is_zero(bucket + sizeof(void *), table->key_length)) {
        memcpy(bucket + sizeof(void *), key, table->key_length);
        memcpy(bucket + sizeof(void *) + table->key_length, data, table->data_size);
    }
    else {
        new_bucket = malloc(table->data_size + table->key_length + sizeof(void *));
        if (!new_bucket) return 1;

        /*insert the bucket to the linked list*/
        memcpy(new_bucket, bucket,sizeof(void *));
        memcpy(bucket, &new_bucket, sizeof(void *));

        memcpy(new_bucket + sizeof(void *), key, table->key_length);
        memcpy(new_bucket + sizeof(void *) + table->key_length, data, table->data_size);
    }
    return 0;
}

int is_zero(unsigned char *buf, size_t size) {
    size_t iter;
    uint_fast64_t res = 0, temp1;
    unsigned char temp2;
    size_t i;

    if (buf == NULL || size == 0) return -1;

    iter = (size / sizeof(uint_fast64_t));
    for (i = 0; i < iter; i++) {
        memcpy(&temp1, buf + i * sizeof(uint_fast64_t), sizeof(uint_fast64_t));
        res |= temp1;
    }
    buf += iter * sizeof(uint_fast64_t);
    for (i = 0; i < size - iter * sizeof(uint_fast64_t); i++) {
        memcpy(&temp2, buf + i, sizeof(unsigned char));
        res |= temp2;
    }

    return res == 0;
}