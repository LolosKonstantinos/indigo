//
// Created by Constantin on 02/01/2026.
//
#include "dpht.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hash_functions.h"

struct dynamic_perfect_hash_table_priv {
    hashFunction hash; //kinda useless, we always use MurMurHash anyway
    first_level_ht_node *hash_table;    //the first level hash table
    size_t cell_count;                  //the number of elements stored currently
    size_t data_size;                   //the number of bytes of the data part of the bucket
    size_t bucket_count;                //the total number of buckets on the first level
    uint32_t key_length;                //the number of bytes of the key part of the buckets
    uint8_t hash_bit_length;            //the nuber of bits we use out of the 32 we get from the hashfunction
    unsigned char zero[3];
};

//todo: !!!!!!!!!IMPORTANT!!!!!!!!VITAL
//TODO: THE SECOND LEVEL HASH TABLE MUST HAVE A SIZE OF N^2, WHERE N IS THE NUMBER OF ELEMENTS IN THE 2ND LEVEL HT
//TODO: THE FIRST LEVEL CAN HAVE SOME MORE NODES THAN K, WHERE K THE TOTAL NUMBER OF ELEMENTS (USE 1.5K)
//TODO: RESIZING THE HASH TABLE MEANS THAT WE RECONSTRUCT THE WHOLE TABLE, BOTH LEVELS


struct first_level_ht_node {
    hashFunction hash;                   //the hash function used for this hash table
    void *second_level_hash_table;       //the second level hash table
    size_t bucket_count;                 //the total number of buckets in the second level
    size_t hash_code;                    //the hash code that corresponds to this hash table //todo: kinda useless
    uint8_t hash_bit_length;             //the length in bits of the hash code
};


dpHashTable *new_dynamic_perfect_hash_table(size_t data_size, size_t key_count,uint32_t max_key_length) {
    //key length longer than 8 bytes is treated as a string (doesn't have to be null terminated)
    dpHashTable *hash_table = malloc(sizeof(dpHashTable));
    if (hash_table == NULL) {
        return NULL;
    }
    //this is ceil(log2(key_count)), but faster
    hash_table->priv->hash_bit_length = (8 * sizeof(int)) - __builtin_clz(key_count -1);

    hash_table->priv = malloc((1<<hash_table->priv->hash_bit_length) * sizeof(first_level_ht_node));
    if (hash_table->priv == NULL) {
        free(hash_table);
        return NULL;
    }
    hash_table->priv->cell_count = key_count;
    hash_table->priv->data_size = data_size;
    hash_table->priv->key_length = max_key_length;
    hash_table->priv->hash = MurMurHash;

    //allocate space for the first hash table, we allocate 1.5 x key_count
    hash_table->priv->hash_table = calloc(key_count + (key_count>>1),sizeof(first_level_ht_node));
    if (hash_table->priv->hash_table == NULL) {
        free(hash_table->priv);
        free(hash_table);
        return NULL;
    }

    return hash_table;
}
void free_dynamic_perfect_hash_table(dpHashTable *table) {}

int dpht_insert(dpHashTable *table, const char *key, size_t key_size, const char *value) {
    uint32_t hash_code;
    dpht_priv *priv;
    first_level_ht_node *node;
    void *new_ht;

    if (table == NULL|| key == NULL || value == NULL) return -1;

    priv = table->priv;

    //hash and keep the bits we care about
    {
        //the key cannot be zero
        //todo what do we want to do here?
        void *temp = 0;
        if (key_size <= sizeof(void *) && memcmp(key,&temp,key_size) == 0)
            return -1;
    }
    hash_code = priv->hash(key,key_size);
    hash_code &= priv->hash_bit_length - 1; //use the hash_bit_length's least significant bits
    node = (priv->hash_table) + hash_code;
    //if it is the first element in the second level, create the second level and return
    if((priv->hash_table)[hash_code].second_level_hash_table == NULL) {
        if (new_second_level_hash_table((priv->hash_table) + hash_code,
                                                priv->data_size,
                                                priv->key_length)) {
            return 1;
                                                }
    }

    priv->bucket_count++;
    //second level must be n^2, we always reconstruct
    {/*todo generally we should first check if the key already exists,
        then check if the previous size is the same as the new one (we use ceil(log2(n)) so this is gonna happen a lot)
        allocate a new table if needed and reconstruct, else put the the new key,
        if we get a collision reconstruct the table with a new hash function,
        if it collides with all functions either use a random salt and go again with murmur hash this time
        as we got a 64byte salt for the keys*/
        //this is ceil(log2(n)) -> size - clz(n-1)
        size_t new_size = (sizeof(size_t)*8) + __builtin_clzll( (priv->data_size + priv->key_length)
            * (node->bucket_count + 1)*(node->bucket_count + 1) -1);

        new_ht = malloc(new_size);
        if (new_ht == NULL) {
            return -1;
        }
        //reconstruct the hash table

        void *curr;
        int new_hash_code;
        for (int i = 1; i < 9; i++) { //one for every hash function (apart murmur hash, as it would collide every node)
            for (size_t j = 0; j < priv->data_size; j++) {
            }
        }
    }
    free(node->second_level_hash_table);
    node->second_level_hash_table = new_ht;
    return 0;
}

int new_second_level_hash_table(first_level_ht_node *node, size_t cell_size, uint32_t key_length) {
    //key length longer than 8 bytes is treated as a string (doesn't have to be null terminated)
    if (key_length > sizeof(void *)) key_length = sizeof(void *);
    //each cell has space for the key and the value
    node->second_level_hash_table = calloc(2, (cell_size + key_length));
    if (node->second_level_hash_table == NULL) {
        return 1;
    }
    node->hash = HF_ARRAY[1];
    node->bucket_count = 2;
    node->hash_bit_length = 1;
    return 0;
}

int resize_first_level_hash_table(dpHashTable *table) {

            //there is a case the new bucket location is occupied by a bucket that must be relocated.
            //relocate the next bucket and then the initial one, in the worst case all buckets need to be relocated.
            //use a stack of the first_level_nodes.
            //also no need to check if the node is already in the stack
            //in all cases there cant be a relocation up, all buckets go down (0 can stay where it was in some cases)
            //so there is no case where two buckets exchange bucket
            //the hash code goes through new_hash = (2 * prev_hash) (+ 1 or +0) new_hash >= prev_hash
    return 0;
}