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
#include "goosetable.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

#define log2_ceil(n) (sizeof(uint64_t) * CHAR_BIT - __builtin_clz(n-1))
#define pow2(n) (1 << (n))

#define BLOCK_SIZE 16

#define BLOCK_EMPTY (0x80)
#define BLOCK_DEAD  (0xff)

//hash big and hash small masks
#define HB_MASK (0x1FFFFFFFFFFFFFFULL)
#define HS_MASK (0x7fULL)

#define byte_pattern_64(p) (0x0101010101010101ULL * (p))
#define zero_bytes_64(n) (((n)-0x0101010101010101ULL) & (~(n)) & 0x8080808080808080ULL)
#define bit_mask_64(n) (((n)*0x0002040810204081ULL))
#define first_on_bit_64(n) (__builtin_ctzll(n))
#define last_on_bit_64(n) (__builtin_clzll(n))
#define get_hs(h) ((char)((h) & HS_MASK))
#define get_hb(h,bits) (((h) >> CHAR_BIT)& ~pow2(bits))

typedef struct {
    union {
#if BLOCK_SIZE == 32
        uint64_t block[4];
        unsigned char block_bytes[32];
#elif BLOCK_SIZE == 64
        uint64_t block[8];
        unsigned char block_bytes[64];
#else
        uint64_t block[2];
        unsigned char block_bytes[16];
#endif
    };
}block_t;

#if BLOCK_SIZE == 32
typedef uint32_t bit_mask_t;
#elif BLOCK_SIZE == 64
typedef uint64_t bit_mask_t;
#else
typedef uint16_t bit_mask_t;
#endif

static hashFunction hash = MurMurHash_64;

typedef union {
    pthread_rwlock_t rw_lock;
    pthread_mutex_t mutex;
}ducktable_lock_t;

struct goosetable_t {
    block_t *blocks;
    unsigned char *keys;
    unsigned char *data;
    uint64_t bucket_count;
    uint64_t data_size;
    int key_size;
    uint8_t hash_bits; //the number of bits we keep from the hash. raised to the power of 2 is the number of blocks
    char zero[3];
    pthread_mutex_t mutex;
};

struct goosetable_iterator_t {
    unsigned char *item_array;
    size_t item_count;
    uint64_t item_size;
    uint64_t current_item;
};

goosetable_t *new_goosetable(int key_size, int data_size, uint64_t init_size,hashFunction hash_function)
{
    goosetable_t *goosetable;
    const uint64_t empty_block = byte_pattern_64(BLOCK_EMPTY);

    if (key_size < 1 || data_size < 1) return NULL;

    goosetable = malloc(sizeof(*goosetable));
    if (goosetable == NULL) {
        return NULL;
    }
    goosetable->data_size = data_size;
    goosetable->key_size = key_size;

    init_size = init_size > 16 ? init_size : 16;
    init_size = log2_ceil(init_size);
    init_size = init_size > 57 ? 57 : init_size;
    goosetable->hash_bits = init_size;
    goosetable->bucket_count = 0;

    goosetable->blocks = malloc(pow2(init_size));
    if (goosetable->blocks == NULL) {
        free(goosetable);
        return NULL;
    }

    //initialize the blocks
    //slow if we can use vectors
    for (uint64_t i = 0; i < pow2(goosetable->hash_bits)*(BLOCK_SIZE/sizeof(empty_block)); i++) {
        memcpy(((unsigned char *)goosetable->blocks) + i*sizeof(empty_block), &empty_block, sizeof(empty_block));
    }

    goosetable->keys = malloc(pow2(init_size) * (key_size + sizeof(uint64_t)));
    if (goosetable->keys == NULL) {
        free(goosetable->blocks);
        free(goosetable);
        return NULL;
    }

    goosetable->data = malloc(pow2(init_size) * (data_size + sizeof(uint64_t)));
    if (goosetable->data == NULL) {
        free(goosetable->blocks);
        free(goosetable->keys);
        free(goosetable);
        return NULL;
    }

    if (pthread_mutex_init(&goosetable->mutex, NULL)) {
        free(goosetable->blocks);
        free(goosetable->keys);
        free(goosetable);
        return NULL;
    }

    return NULL;
}
void free_goosetable(goosetable_t *goosetable)
{
    free(goosetable->blocks);
    free(goosetable->keys);
    pthread_mutex_destroy(&goosetable->mutex);
    free(goosetable);
}

static FORCE_INLINE uint16_t get_bit_map(const block_t *const block,const uint8_t hs)
{
    uint16_t bit_mask = 0;
    const uint64_t cmp_vector = byte_pattern_64(hs);
    uint64_t xor_vector = 0;

    xor_vector = cmp_vector ^ block->block[0];
    bit_mask |= (uint16_t)((bit_mask_64(zero_bytes_64(xor_vector))>>56)&0x00ff);
    xor_vector = cmp_vector ^ block->block[1];
    bit_mask |= (uint16_t)((bit_mask_64(zero_bytes_64(xor_vector))>>48)&0xff00);
    return bit_mask;
}

int goosetable_search(goosetable_t *goosetable,const char *restrict key)
{
    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;

    if (!goosetable || !key) return -1;

    hash_val = hash(key, goosetable->key_size);
    hs = get_hs(hash_val);
    hb = get_hb(hash_val, goosetable->hash_bits);

    //for every block
    for (uint64_t i = 0; i < pow2(goosetable->hash_bits); i++) {
        //create the bit map
        candidate_bit_map = get_bit_map(goosetable->blocks + hb + i, hs);

        //check every matching item in the block
        while (candidate_bit_map != 0) {
            if (memcmp(key,
                goosetable->keys +
                (((hb + i)%pow2(goosetable->hash_bits))*BLOCK_SIZE /*move to the block*/
                +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                *(goosetable->key_size + sizeof(uint64_t))+ sizeof(uint64_t),
                goosetable->key_size) == 0)
            {
                return 1;
            }
            //we checked this one so we turn of the respective bit
            candidate_bit_map &= (0xfffe)<<first_on_bit_64(candidate_bit_map);
        }
        //check if the block has empty cells.
        //if there is at least one empty that means it was never inserted
        if (get_bit_map(goosetable->blocks + (hb + i)%pow2(goosetable->hash_bits), BLOCK_EMPTY)) {
            return 0;
        }
    }
    return 0;
}
int goosetable_retrieve(goosetable_t *goosetable,const char *restrict key, void *restrict data)
{
    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;

    if (!goosetable || !key || !data) return -1;

    hash_val = hash(key, goosetable->key_size);
    hs = get_hs(hash_val);
    hb = get_hb(hash_val, goosetable->hash_bits);

    //for every block
    for (uint64_t i = 0; i < pow2(goosetable->hash_bits); i++) {
        //create the bit map
        candidate_bit_map = get_bit_map(goosetable->blocks + hb + i, hs);

        //check every matching item in the block
        while (candidate_bit_map != 0) {
            if (memcmp(key,
                goosetable->keys
                +(((hb + i)%pow2(goosetable->hash_bits)) * BLOCK_SIZE /*move to the block*/
                +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                *(goosetable->key_size + sizeof(uint64_t)) + sizeof(uint64_t),
                goosetable->key_size) == 0)
            {
                //copy the index
                const uint64_t idx = *((uint64_t *)(goosetable->keys
                                    +(((hb + i)%pow2(goosetable->hash_bits)) * BLOCK_SIZE /*move to the block*/
                                    +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                                    *(goosetable->key_size + sizeof(uint64_t))));

                // copy the data part to return it to the user
                memcpy(data,goosetable->data + idx*(goosetable->data_size + sizeof(uint64_t)), goosetable->data_size);
                return 1;
            }
            //we checked this one so we turn of the respective bit
            candidate_bit_map &= (0xfffe)<<first_on_bit_64(candidate_bit_map);
        }
        //check if the block has empty cells.
        //if there is at least one empty that means it was never inserted
        if (get_bit_map(goosetable->blocks + (hb + i)%pow2(goosetable->hash_bits), BLOCK_EMPTY)) {
            return 0;
        }
    }
    return 0;
}
int goosetable_access(goosetable_t *goosetable,const char *restrict key, void **data)
{
    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;

    if (!goosetable || !key) return -1;

    hash_val = hash(key, goosetable->key_size);
    hs = get_hs(hash_val);
    hb = get_hb(hash_val, goosetable->hash_bits);

    //for every block
    for (uint64_t i = 0; i < pow2(goosetable->hash_bits); i++) {
        //create the bit map
        candidate_bit_map = get_bit_map(goosetable->blocks + hb + i, hs);

        //check every matching item in the block
        while (candidate_bit_map != 0) {
            if (memcmp(key,
                goosetable->keys +
                (((hb + i)%pow2(goosetable->hash_bits)) * BLOCK_SIZE /*move to the block*/
                +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                *(goosetable->key_size + sizeof(uint64_t)) + sizeof(uint64_t),
                goosetable->key_size) == 0)
            {
                const uint64_t idx = *(uint64_t *)(goosetable->keys
                                   +(((hb + i) % pow2(goosetable->hash_bits)) * BLOCK_SIZE /*move to the block*/
                                   + first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                                   * (goosetable->key_size + sizeof(uint64_t)));
                *data = goosetable->data + idx*(goosetable->data_size + sizeof(uint64_t));
                return 1;
            }
            //we checked this one so we turn of the respective bit
            candidate_bit_map &= (0xfffe)<<first_on_bit_64(candidate_bit_map);
        }
        //check if the block has empty cells.
        //if there is at least one empty that means it was never inserted
        if (get_bit_map(goosetable->blocks + (hb + i)%pow2(goosetable->hash_bits), BLOCK_EMPTY)) {
            return 0;
        }
    }
    return 0;
}
static int expand_goosetable(goosetable_t *const restrict goosetable)
{
    unsigned char *restrict new_table;
    block_t *restrict new_blocks;
    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;
    uint16_t occupied_bit_map = 0;
    void *key;
    const uint64_t empty_block = byte_pattern_64(BLOCK_EMPTY);

    if (!goosetable) return -1;
    if (goosetable->hash_bits >= 57) return 1;
    ++(goosetable->hash_bits);

    //allocate new data array and re-hash the whole table
    new_table = malloc(pow2(goosetable->hash_bits) * goosetable->key_size);
    new_blocks = malloc(pow2(goosetable->hash_bits) * BLOCK_SIZE);
    key = malloc(goosetable->key_size);
    if (!new_table || !new_blocks ||!key) {
        free(new_table);
        free(new_blocks);
        free(key);
        --(goosetable->hash_bits);
        return -1;
    }

    {
        void* temp = realloc(goosetable->data, pow2(goosetable->hash_bits)*(goosetable->data_size));
        if (!temp) {
            free(new_table);
            free(new_blocks);
            free(key);
            --(goosetable->hash_bits);
            return -1;
        }
        goosetable->data = temp;
    }

    //initialize the blocks
    //slow if we can use vectors
    for (uint64_t i = 0; i < pow2(goosetable->hash_bits)*(BLOCK_SIZE/sizeof(empty_block)); i++) {
        memcpy(((unsigned char *)new_blocks) + i*sizeof(empty_block), &empty_block, sizeof(empty_block));
    }

    //we need to insert every key and data pair to the new table

    //for every old block
    for (uint64_t i = 0; i < pow2(goosetable->hash_bits - 1); i++) {
        //find the cells that are not empty and not removed elements
        //thus the cells that hold an element
        occupied_bit_map = get_bit_map(goosetable->blocks + i,BLOCK_EMPTY);
        occupied_bit_map += get_bit_map(goosetable->blocks + i,BLOCK_DEAD);
        occupied_bit_map = ~occupied_bit_map;

        while (occupied_bit_map != 0) {
            memcpy(key,
                  goosetable->keys + (i*BLOCK_SIZE + first_on_bit_64(occupied_bit_map))
                  * (goosetable->key_size + sizeof(uint64_t)) + sizeof(uint64_t),
                   goosetable->key_size);

            //do a modified insert
            //hash the key
            hash_val = hash(key, goosetable->key_size);
            hs = get_hs(hash_val);
            hb = get_hb(hash_val, goosetable->hash_bits);

            //for every block in the new table
            for (uint64_t k = 0; k < pow2(goosetable->hash_bits); k++) {
                //check if the block has empty cells.
                candidate_bit_map = get_bit_map(goosetable->blocks + (hb + k)%pow2(goosetable->hash_bits), BLOCK_EMPTY);
                if (candidate_bit_map) {
                    // we found an empty slot thus we insert it here
                    const char idx = first_on_bit_64(candidate_bit_map);
                    //(hb/16 +16*i + idx
                    //TRANSLATION:
                    //hb/16 is the 16 item block possession
                    //16*i is how many block away from the original block we found an empty spot
                    //idx is the index inside the block [0,15]
                    memcpy(new_table + (((hb + k)%pow2(goosetable->hash_bits))*BLOCK_SIZE + idx)*(goosetable->key_size + sizeof(uint64_t)),
                           goosetable->keys + (i*BLOCK_SIZE + first_on_bit_64(occupied_bit_map)) * (goosetable->key_size + sizeof(uint64_t)),
                           goosetable->key_size + sizeof(uint64_t));

                    new_blocks[(hb + k)%pow2(goosetable->hash_bits)].block_bytes[idx] = hs;

                    //we checked this one so we turn of the respective bit
                    occupied_bit_map &= (0xfffe)<<first_on_bit_64(occupied_bit_map);
                    break;
                }
            }
        }
    }

    free(key);
    //reuse key as a temporary pointer
    key = goosetable->blocks;
    goosetable->blocks = new_blocks;
    free(key);
    key = goosetable->data;
    goosetable->data = new_table;
    free(key);

    return 0;
}

int goosetable_insert(goosetable_t *goosetable,const char *restrict key,const char *restrict data)
{
    if (!goosetable || !key || !data) return -1;

    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;

    if (!goosetable || !key) return -1;

    //check if we need to resize
    if ( goosetable->bucket_count+1 > pow2(goosetable->hash_bits)/(goosetable->data_size) ) {
        // we need to resize
        const int ret = expand_goosetable(goosetable);
        if (ret != 0) {
            return ret;
        }
    }

    hash_val = hash(key, goosetable->key_size);
    hs = get_hs(hash_val);
    hb = get_hb(hash_val, goosetable->hash_bits);

    //do a modified search
    for (uint64_t i = 0; i < pow2(goosetable->hash_bits); i++) {
        //create the bit map
        candidate_bit_map = get_bit_map(goosetable->blocks + (hb + i)%pow2(goosetable->hash_bits), hs);
        while (candidate_bit_map != 0) {
            if (memcmp(key,
                goosetable->keys +
                (((hb + i)%pow2(goosetable->hash_bits))*BLOCK_SIZE /* move to the block*/
                +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                *(goosetable->key_size + sizeof(uint64_t)) + sizeof(uint64_t), /*times the size of a bucket*/
                goosetable->key_size) == 0)
            {
                return 1;
            }

            //we checked this one so we turn of the respective bit
            candidate_bit_map &= (0xfffe)<<first_on_bit_64(candidate_bit_map);
        }
        //check if the block has empty cells.
        //if there is at least one empty that means it was never inserted
        if (get_bit_map(goosetable->blocks + (hb + i)%pow2(goosetable->hash_bits), BLOCK_EMPTY)) {
            // we found an empty slot thus we insert it here
            //(hb + i)%pow2(ducktable->hash_bits) + idx
            //TRANSLATION:
            //(hb + i)%pow2(ducktable->hash_bits) is the block we found free
            //idx is the index inside the block [0,15]
            const char idx = first_on_bit_64(~candidate_bit_map);
            const uint64_t key_idx =
                (((hb + i)%pow2(goosetable->hash_bits))*BLOCK_SIZE + idx)*(goosetable->key_size + sizeof(uint64_t));


            memcpy(goosetable->keys +key_idx, &(goosetable->bucket_count),sizeof(uint64_t));
            memcpy(goosetable->keys +key_idx + sizeof(uint64_t) ,key,goosetable->key_size);

            //write the data to the data array
            memcpy(goosetable->data + goosetable->bucket_count * (sizeof(uint64_t) + goosetable->data_size)
                    ,&key_idx,sizeof(uint64_t));

            memcpy(goosetable->data + goosetable->bucket_count * (sizeof(uint64_t) + goosetable->data_size) + sizeof(uint64_t)
                   ,data,goosetable->data_size);

            goosetable->blocks[(hb + i)%pow2(goosetable->hash_bits)].block_bytes[idx] = hs;

            ++(goosetable->bucket_count);
            return 0;
        }
    }

    return 0;
}
int goosetable_remove(goosetable_t *goosetable,const char *restrict key)
{
    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;

    if (!goosetable || !key) return -1;

    hash_val = hash(key, goosetable->key_size);
    hs = get_hs(hash_val);
    hb = get_hb(hash_val, goosetable->hash_bits);

    //for every block
    for (uint64_t i = 0; i < pow2(goosetable->hash_bits); i++) {
        //create the bit map
        candidate_bit_map = get_bit_map(goosetable->blocks + hb + i, hs);

        //check every matching item in the block
        while (candidate_bit_map != 0) {
            if (memcmp(key,
                goosetable->keys +
                (((hb + i)%pow2(goosetable->hash_bits))*BLOCK_SIZE /* move to the block*/
                +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                *(goosetable->key_size + sizeof(uint64_t)) + sizeof(uint64_t), /*times the size of a bucket*/
                goosetable->key_size) == 0)
            {
                const uint64_t removed_idx = *((uint64_t *)(goosetable->keys
                                    +(((hb + i)%pow2(goosetable->hash_bits)) * BLOCK_SIZE /*move to the block*/
                                    +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                                    *(goosetable->key_size + sizeof(uint64_t))));

                const uint64_t replacement_idx = *(uint64_t *)(goosetable->data
                                                            + (goosetable->bucket_count -1)
                                                            * (sizeof(uint64_t) + goosetable->data_size));

                //if the removed node is not the last node in the data array
                if (removed_idx != goosetable->bucket_count - 1) {
                    //move the last node to the place of the removed node
                    memcpy(goosetable->data +(removed_idx*(goosetable->data_size + sizeof(uint64_t))),
                           goosetable->data + (goosetable->bucket_count -1) * (sizeof(uint64_t) + goosetable->data_size),
                           goosetable->data_size + sizeof(uint64_t));
                    //edit the key to have the right index stored
                    memcpy(goosetable->keys + replacement_idx, &removed_idx, sizeof(uint64_t));
                }

                //edit the block to remove the item
                goosetable->blocks[(hb + i)%pow2(goosetable->hash_bits)]
                .block_bytes[first_on_bit_64(candidate_bit_map)]= BLOCK_DEAD;
                --(goosetable->bucket_count);
                return 0;
            }
            //we checked this one so we turn of the respective bit
            candidate_bit_map &= (0xfffe)<<first_on_bit_64(candidate_bit_map);
        }
        //check if the block has empty cells.
        //if there is at least one empty that means it was never inserted
        if (get_bit_map(goosetable->blocks + (hb + i)%pow2(goosetable->hash_bits), BLOCK_EMPTY)) {
            return 1;
        }
    }
    return 1;
}

int new_goosetable_iterator(goosetable_t *goosetable,goosetable_iterator_t **iterator)
{
    if (!goosetable || !iterator) return -1;
    goosetable_iterator_t *const restrict iter = malloc(sizeof(goosetable_iterator_t));
    if (!iter) return -1;
    iter->current_item = 0;
    iter->item_count = goosetable->bucket_count;
    iter->item_size = goosetable->data_size;
    iter->item_array = goosetable->data;
    *iterator = iter;
    return 0;
}
void free_goosetable_iterator(goosetable_iterator_t **iterator)
{
    if (!iterator) return;
    free(*iterator);
    *iterator = NULL;
}
int goosetable_has_next(goosetable_iterator_t *iterator)
{
    if (!iterator) return 0;
    if (iterator->current_item >= iterator->item_count) return 0;
    return 1;
}
void *goosetable_next(goosetable_iterator_t *iterator)
{
    void *item;
    if (!iterator) return NULL;
    if (iterator->current_item >= iterator->item_count) return NULL;
    item = iterator->item_array + iterator->current_item *(iterator->item_size + sizeof(uint64_t));
    iterator->current_item++;
    return item;
}

int goosetable_iterator_remove_current(goosetable_t *goosetable, goosetable_iterator_t *iterator)
{
    if (!goosetable || !iterator) return -1;
    if (iterator->current_item >= iterator->item_count || iterator->current_item == 0) return -1;

    const uint64_t removed_idx = *(uint64_t *)(goosetable->data
                                    + (iterator->current_item - 1) * (iterator->item_size + sizeof(uint64_t)));

    const uint64_t replacement_idx = *(uint64_t *)(goosetable->data
                                                + (goosetable->bucket_count -1)
                                                * (sizeof(uint64_t) + goosetable->data_size));

    //if the removed node is not the last node in the data array
    if (iterator->current_item - 1 != goosetable->bucket_count - 1) {
        //move the last node to the place of the removed node
        memcpy(goosetable->data + ((iterator->current_item - 1) * (goosetable->data_size + sizeof(uint64_t))),
               goosetable->data + (goosetable->bucket_count - 1) * (sizeof(uint64_t) + goosetable->data_size),
               goosetable->data_size + sizeof(uint64_t));
        //edit the key to have the right index stored
        memcpy(goosetable->keys + replacement_idx, &removed_idx, sizeof(uint64_t));
    }

    //edit the block to remove the item
    *((unsigned char *)(goosetable->blocks) + removed_idx/(goosetable->key_size + sizeof(uint64_t)))= BLOCK_DEAD;
    --(goosetable->bucket_count);
    return 0;
}

void goosetable_lock(goosetable_t *restrict goosetable)
{
    if (!goosetable) return;
    pthread_mutex_lock(&goosetable->mutex);
}
void goosetable_unlock(goosetable_t *restrict goosetable)
{
    if (!goosetable) return;
    pthread_mutex_unlock(&goosetable->mutex);
}
