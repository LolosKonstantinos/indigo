/*
Copyright (c) 2026 Lolos Konstantinos

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

#include "lht.h"
#include <pthread.h>
#include <hash_functions.h>
#include <stdlib.h>
#include <string.h>


struct lht_priv {
    lht_node_t *head;           //the head of the linked list
    hashFunction hash;          //kinda useless, we always use MurMurHash anyway
    unsigned char *table;       //the array of the hash table
    size_t data_size;           //the number of bytes of the data part of the bucket
    size_t bucket_count;        //the total number of buckets on the first level
    uint32_t key_length;        //the number of bytes of the key part of the buckets
    uint8_t hash_bit_length;    //the nuber of bits we use out of the 32 we get from the hashfunction
    unsigned char zero[3];
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

int is_zero(const unsigned char * buf, const size_t size) {
    size_t iter;
    uint_fast64_t res = 0;
    uint_fast64_t temp1;
    unsigned char temp2;
    size_t i;

    if (buf == NULL || size == 0) return -1;

    iter = (size / sizeof(uint_fast64_t));
    for (i = 0; i < iter; i++) {
        memcpy(&temp1, buf + (i * sizeof(uint_fast64_t)), sizeof(uint_fast64_t));
        res |= temp1;
    }
    buf += iter * sizeof(uint_fast64_t);
    for (i = 0; i < size - (iter * sizeof(uint_fast64_t)); i++) {
        memcpy(&temp2, buf + i, sizeof(unsigned char));
        res |= temp2;
    }

    return res == 0;
}

lht_t *new_lht(size_t data_size, size_t key_length, size_t init_size) {
    lht_priv *priv;
    lht_t *ht;
    if (data_size == 0) {
        return NULL;
    }
    ht = (lht_t *)malloc(sizeof(lht_t));
    if (ht == NULL) return NULL;
    priv = malloc(sizeof(lht_priv));
    if (priv == NULL) {
        free(ht);
        return NULL;
    }
    pthread_mutex_init(&priv->mutex, NULL);
    pthread_cond_init(&priv->cond, NULL);
    ht->private = priv;
    priv->head = NULL;
    priv->hash = FastHash;
    priv->bucket_count = init_size ? init_size : 1;
    priv->hash_bit_length = (sizeof(size_t) * 8) - __builtin_ctz((init_size * init_size) - 1);
    priv->data_size = data_size;
    priv->key_length = key_length ? key_length : sizeof(uint32_t);
    priv->table = (unsigned char *)malloc((1<<priv->hash_bit_length) * ((sizeof(void *)<<1) + priv->data_size + priv->key_length));
    if (priv->table == NULL) {
        free(priv);
        free(ht);
        return NULL;
    }
    ht->insert = lht_insert;
    ht->remove = lht_delete;
    ht->search = lht_search;
    return ht;
}
void delete_hash_table(lht_t *ht) {
    if (!ht || !ht->private) return;
    lht_priv *priv = ht->private;
    void * temp;
    void *prev = NULL;
    pthread_mutex_destroy(&ht->private->mutex); //I don't really know what to do with this?
    pthread_cond_destroy(&ht->private->cond);

    // remove the linked list nodes
    for (lht_node_t *curr = priv->head; curr != NULL; curr = curr->next) {
        temp = *((void **)(curr->data - priv->key_length - (sizeof(void *)<<1)));
        if (temp == NULL) continue;
        free(curr->data - priv->key_length - (sizeof(void *)<<1));
        free(curr->prev);
        prev = curr;
    }
    free(prev);
    free(ht->private->table);
    free(ht->private);
    free(ht);
}

int lht_insert(lht_t *ht, void *key, void *data){
    //the hash table should have a size of (at least) n^2 where n is the number of buckets
    size_t new_size;
    size_t old_size;
    lht_priv *priv;
    unsigned int hash_code;

    unsigned char *bucket;
    unsigned char *new_bucket;
    unsigned char *new_table;

    lht_node_t *new_node;

    if (!ht || !key || !data) {
        return -1;
    }

    if (lht_search(ht,key) != NULL) return -1;

    priv = ht->private;

    new_node = malloc(sizeof(lht_node_t));
    if (!new_node) {
        return 1;
    }

    pthread_mutex_lock(&priv->mutex);
    new_size = (sizeof(size_t) * 8) - __builtin_clzll(((priv->bucket_count+1) + ((priv->bucket_count+1)>>1)) - 1);
    old_size = priv->hash_bit_length;
    if (old_size >= new_size) {
        //we don't need to allocate more memory
        hash_code = priv->hash(key,priv->key_length);
        hash_code &= (1<<priv->hash_bit_length) - 1;
        bucket = priv->table + (hash_code * (priv->data_size + priv->key_length + sizeof(void *)));
        /*if the key is 0 then the bucket is empty and ready to use*/
        if (is_zero(bucket + (sizeof(void *)<<1), priv->key_length)) {
            memcpy(bucket + (sizeof(void *)<<1), key, priv->key_length);
            memcpy(bucket + (sizeof(void *)<<1) + priv->key_length, data, priv->data_size);
        }
        else {
            new_bucket = malloc(priv->data_size + priv->key_length + (sizeof(void *)<<1));
            if (!new_bucket) {
                pthread_mutex_unlock(&priv->mutex);
                free(new_node);
                return 1;
            }

            /*insert the bucket to the linked list*/
            memcpy(new_bucket, bucket,sizeof(void *));
            memcpy(bucket, &new_bucket, sizeof(void *));

            memcpy(new_bucket + (sizeof(void *)<<1), key, priv->key_length);
            memcpy(new_bucket + (sizeof(void *)<<1) + priv->key_length, data, priv->data_size);
            bucket = new_bucket; // so that we can universally add the node to the list
        }
    }
    else {
        /*we need to resize the hash table (allocate a new table and move all the previous buckets to the new table)*/
        new_table = malloc((1<<new_size) * ((sizeof(void *)<<1) + priv->key_length + priv->data_size));
        if (!new_table) {
            pthread_mutex_unlock(&priv->mutex);
            free(new_node);
            return 1;
        }
        priv->hash_bit_length += 1;
        for (size_t i = 0; i < old_size; i++) {
            bucket = priv->table + (i * (sizeof(void*) + priv->key_length+priv->data_size));
            if (is_zero(bucket + sizeof(void *), priv->key_length)) continue;

            for (unsigned char * b = bucket; b != NULL; b = *(void**)b) {
                hash_code = priv->hash((char *)b + sizeof(void*),priv->key_length);
                hash_code &= (1<<priv->hash_bit_length) - 1;

                new_bucket = new_table + (hash_code * (priv->data_size + priv->key_length + sizeof(void *)));
                if (lht_bucket_insert(priv,new_bucket,b + sizeof(void *),b + sizeof(void *) + priv->key_length)){
                    free(new_table);
                    priv->hash_bit_length -= 1;
                    pthread_mutex_unlock(&priv->mutex);
                    free(new_node);
                    return 1;
                }
            }
        }

        free(priv->table); //todo is this safe? are the linked list nodes deleted
        priv->table = new_table;

        /*the old table has been resized, now we insert the new element*/

        hash_code = priv->hash(key,priv->key_length);
        hash_code &= (1<<priv->hash_bit_length) - 1;
        bucket = priv->table + (hash_code * (priv->data_size + priv->key_length + sizeof(void *)));
        lht_bucket_insert(priv,bucket,key,data);
    }

    //add the pointer to the data
    new_node->data = bucket + sizeof(void *) + priv->key_length;
    memcpy(bucket + sizeof(void *), &new_node, sizeof(void *));

    //attach the node to the list
    if (priv->head) {
        new_node->next = priv->head;
        new_node->next->prev = new_node;
        new_node->prev = NULL;
        priv->head = new_node;
    }
    else{
        priv->head = new_node;
        new_node->next = NULL;
        new_node->prev = NULL;
    }

    priv->bucket_count++;

    pthread_mutex_unlock(&priv->mutex);

    return 0;
}

void *lht_search(lht_t *ht, void *key) {
    unsigned int hash_code;
    unsigned char *bucket;
    lht_priv *priv;

    if (!ht || !key) {
        return NULL;
    }
    priv = ht->private;

    pthread_mutex_lock(&priv->mutex);

    hash_code = priv->hash(key,priv->key_length);
    hash_code &= (1<<priv->hash_bit_length) - 1;
    bucket = priv->table + (hash_code * (priv->data_size + priv->key_length + (sizeof(void *)<<1)));

    while (memcmp(key,bucket + (sizeof(void *)<<1), priv->key_length) != 0) {
        bucket = *(void **)bucket;
        if (!bucket) {
            pthread_mutex_unlock(&priv->mutex);
            return NULL;
        }
    }
    pthread_mutex_unlock(&priv->mutex);
    return bucket + sizeof(void *) + priv->key_length;
}

int lht_delete(linked_hash_table_t *ht, void *key) {
    unsigned int hash_code;
    unsigned char *bucket;
    unsigned char *prev = NULL;
    unsigned char *temp;
    unsigned char *new_bucket;
    unsigned char *new_table;
    size_t old_size;
    size_t new_size;
    lht_node_t *list_node;
    lht_node_t *temp_node;
    lht_priv *priv;
    if (!ht || !key) {
        return -1;
    }
    priv = ht->private;

    pthread_mutex_lock(&priv->mutex);

    hash_code = priv->hash(key,priv->key_length);
    hash_code &= (1<<priv->hash_bit_length) - 1;
    bucket = priv->table + (hash_code * (priv->data_size + priv->key_length + (sizeof(void *)<<1)));
    while (memcmp(key,bucket + (sizeof(void *)<<1), priv->key_length) != 0) {
        prev = bucket;
        bucket = *(void **)bucket;
        if (!bucket) {
            pthread_mutex_unlock(&priv->mutex);
            return 1;
        }
    }

    //get the address of the list node
    list_node = *((void **)(bucket + sizeof(void *)));

    //remove the node from the list
    if (list_node == priv->head) {
        temp_node = list_node->next;
        priv->head = temp_node;
        temp_node->prev = NULL;
        free(list_node);
    }
    else {
        temp_node = list_node;
        list_node->next->prev = list_node->prev;
        list_node->prev->next = list_node->next;
        free(temp_node);
    }

    if (!prev) {
        //if we delete the head of the list (the node in the table), we need to move the next node to the table
        temp = *(void **)bucket;
        if (temp) {
            memcpy(bucket, temp, (sizeof(void *)<<1) + priv->key_length + priv->data_size);
            free(temp);
        }
        else {
            //there is no other node so we just zero out the bucket
            memset(bucket, 0, (sizeof(void *)<<1) + priv->key_length + priv->data_size);
        }
    }
    else {
        memcpy(prev, bucket, sizeof(void *));
        free(bucket);
    }

    old_size = priv->hash_bit_length;
    priv->bucket_count--;
    new_size = (sizeof(size_t) * 8) - __builtin_clzll((priv->bucket_count + (priv->bucket_count>>1)) - 1);

    if (new_size < old_size) {
        /*we need to resize the hash table (allocate a new table and move all the previous buckets to the new table)*/
        new_table = malloc((1<<new_size) * ((sizeof(void *)<<1) + priv->key_length + priv->data_size));
        if (!new_table) {
            pthread_mutex_unlock(&priv->mutex);
            return 1;
        }
        priv->hash_bit_length += 1;
        for (size_t i = 0; i < old_size; i++) {
            bucket = priv->table + (i * ((sizeof(void*)<<1) + priv->key_length + priv->data_size));
            if (is_zero(bucket + (sizeof(void *)<<1), priv->key_length)) continue;

            for (unsigned char * b = bucket; b != NULL; b = *(void**)b) {
                hash_code = priv->hash((char *)b + (sizeof(void*)<<1),priv->key_length);
                hash_code &= (1<<priv->hash_bit_length) - 1;

                new_bucket = new_table + (hash_code * (priv->data_size + priv->key_length + sizeof(void *)));
                if (lht_bucket_insert(priv,new_bucket,b + (sizeof(void *)<<1),b + (sizeof(void *)<<1) + priv->key_length)){
                    free(new_table);
                    priv->hash_bit_length -= 1;
                    pthread_mutex_unlock(&priv->mutex);
                    return 1;
                }
            }
        }

        free(priv->table);
        priv->table = new_table;
    }
    pthread_mutex_unlock(&priv->mutex);
    return 0;
}

int lht_bucket_insert(const lht_priv *table, unsigned char *bucket, const void *key, const void *data) {
    unsigned char *new_bucket;

    if (is_zero(bucket + (sizeof(void *)<<1), table->key_length)) {
        memcpy(bucket + (sizeof(void *)<<1), key, table->key_length);
        memcpy(bucket + (sizeof(void *)<<1) + table->key_length, data, table->data_size);
    }
    else {
        new_bucket = malloc(table->data_size + table->key_length + (sizeof(void *)<<1));
        if (!new_bucket) return 1;

        /*insert the bucket to the linked list*/
        memcpy(new_bucket, bucket,sizeof(void *));
        memcpy(bucket, &new_bucket, sizeof(void *));

        memcpy(new_bucket + sizeof(void *), key, table->key_length);
        memcpy(new_bucket + sizeof(void *) + table->key_length, data, table->data_size);
    }
    return 0;
}

int lht_lock(lht_t *ht) {
    if (!ht) return 1;
    if (!ht->private) return 1;
    pthread_mutex_lock(&(ht->private->mutex));
    return 0;
}
int lht_unlock(lht_t *ht) {
    if (!ht) return 1;
    if (!ht->private) return 1;
    pthread_mutex_unlock(&(ht->private->mutex));
    return 0;
}

int lht_list(lht_t *ht, lht_node_t *list) {
    if (!list || !ht || !ht->private) return 1;

    *list = *(ht->private->head);
    return 0;
}