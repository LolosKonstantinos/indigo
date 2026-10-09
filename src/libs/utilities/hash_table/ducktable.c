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
#include "ducktable.h"
#include "hash_functions.h"
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>

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

struct ducktable_t {
    block_t *blocks;
    void *data;
    uint64_t bucket_count;
    uint64_t data_size;
    int key_size;
    int key_offset;
    uint8_t hash_bits; //the number of bits we keep from the hash. raised to the power of 2 is the number of blocks
    char zero[7];
    pthread_mutex_t mutex;
};

static FORCE_INLINE char find_zero_64(const uint64_t n)
{
    if (n == ULLONG_MAX) return -1;
    return last_on_bit_64(~n);
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

ducktable_t *new_ducktable(int key_size, int key_offset, int data_size, uint64_t init_size)
{
    ducktable_t *restrict ducktable;
    const uint64_t empty_block = byte_pattern_64(BLOCK_EMPTY);

    if (key_size < 1 || data_size < 1) return NULL;

    ducktable = malloc(sizeof(*ducktable));
    if (ducktable == NULL) {
        return NULL;
    }
    ducktable->data_size = data_size;
    ducktable->key_size = key_size;
    ducktable->key_offset = key_offset;

    init_size = init_size > 16 ? init_size : 16;
    init_size = log2_ceil(init_size);
    init_size = init_size > 57 ? 57 : init_size;
    ducktable->hash_bits = init_size;
    ducktable->bucket_count = 0;

    ducktable->blocks = malloc(pow2(init_size));
    if (ducktable->blocks == NULL) {
        free(ducktable);
        return NULL;
    }

    //initialize the blocks
    //slow if we can use vectors
    for (uint64_t i = 0; i < pow2(ducktable->hash_bits)*(BLOCK_SIZE/sizeof(empty_block)); i++) {
        memcpy(((unsigned char *)ducktable->blocks) + i*sizeof(empty_block), &empty_block, sizeof(empty_block));
    }

    ducktable->data = malloc(pow2(init_size) * data_size);
    if (ducktable->data == NULL) {
        free(ducktable->blocks);
        free(ducktable);
        return NULL;
    }

    return ducktable;
}

void free_ducktable(ducktable_t *restrict ducktable)
{
    free(ducktable->blocks);
    free(ducktable->data);
    free(ducktable);
}

static int expand_ducktable(ducktable_t *const restrict ducktable)
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

    if (!ducktable) return -1;
    if (ducktable->hash_bits >= 57) return 1;
    ++(ducktable->hash_bits);

    //allocate new data array and re-hash the whole table
    new_table = malloc(pow2(ducktable->hash_bits) * ducktable->data_size);
    new_blocks = malloc(pow2(ducktable->hash_bits) * BLOCK_SIZE);
    key = malloc(ducktable->key_size);
    if (!new_table || !new_blocks || !key) {
        free(new_table);
        free(new_blocks);
        free(key);
        --(ducktable->hash_bits);
        return -1;
    }

    //initialize the blocks
    //slow if we can use vectors
    for (uint64_t i = 0; i < pow2(ducktable->hash_bits)*(BLOCK_SIZE/sizeof(empty_block)); i++) {
        memcpy(((unsigned char *)new_blocks) + i*sizeof(empty_block), &empty_block, sizeof(empty_block));
    }

    //we need to insert every key and data pair to the new table

    //for every old block
    for (uint64_t i = 0; i < pow2(ducktable->hash_bits - 1); i++) {
        //find the cells that are not empty and not removed elements
        //thus the cells that hold an element
        occupied_bit_map = get_bit_map(ducktable->blocks + i,BLOCK_EMPTY);
        occupied_bit_map += get_bit_map(ducktable->blocks + i,BLOCK_DEAD);
        occupied_bit_map = ~occupied_bit_map;

        while (occupied_bit_map != 0) {
            memcpy(key,
                  ducktable->data
                   + (i*BLOCK_SIZE + first_on_bit_64(occupied_bit_map)) * (ducktable->data_size) + ducktable->key_offset,
                   ducktable->key_size);

            //do a modified insert
            //hash the key
            hash_val = hash(key, ducktable->key_size);
            hs = get_hs(hash_val);
            hb = get_hb(hash_val, ducktable->hash_bits);

            //for every block in the new table
            for (uint64_t k = 0; k < pow2(ducktable->hash_bits); k++) {
                //check if the block has empty cells.
                candidate_bit_map = get_bit_map(ducktable->blocks + (hb + k)%pow2(ducktable->hash_bits), BLOCK_EMPTY);
                if (candidate_bit_map) {
                    // we found an empty slot thus we insert it here
                    const char idx = first_on_bit_64(candidate_bit_map);
                    //(hb/16 +16*i + idx
                    //TRANSLATION:
                    //hb/16 is the 16 item block possession
                    //16*i is how many block away from the original block we found an empty spot
                    //idx is the index inside the block [0,15]
                    memcpy(new_table + (((hb + k)%pow2(ducktable->hash_bits)) + idx)*(ducktable->data_size),
                            ducktable->data + (i + first_on_bit_64(occupied_bit_map)) * (ducktable->data_size),
                            ducktable->data_size);

                    new_blocks[(hb + k)%pow2(ducktable->hash_bits)].block_bytes[idx] = hs;

                    //we checked this one so we turn of the respective bit
                    occupied_bit_map &= (0xfffe)<<first_on_bit_64(occupied_bit_map);
                    break;
                }
            }
        }
    }

    free(key);
    //reuse key as a temporary pointer
    key = ducktable->blocks;
    ducktable->blocks = new_blocks;
    free(key);
    key = ducktable->data;
    ducktable->data = new_table;
    free(key);

    return 0;
}

int ducktable_search(ducktable_t *const restrict ducktable,const char *restrict const key)
{
    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;

    if (!ducktable || !key) return -1;

    hash_val = hash(key, ducktable->key_size);
    hs = get_hs(hash_val);
    hb = get_hb(hash_val, ducktable->hash_bits);

    //for every block
    for (uint64_t i = 0; i < pow2(ducktable->hash_bits); i++) {
        //create the bit map
        candidate_bit_map = get_bit_map(ducktable->blocks + hb + i, hs);

        //check every matching item in the block
        while (candidate_bit_map != 0) {
            if (memcmp(key,
                ducktable->data +
                (((hb + i)%pow2(ducktable->hash_bits))*BLOCK_SIZE /*move to the block*/
                +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                *(ducktable->data_size) + ducktable->key_offset,
                ducktable->key_size) == 0)
            {
                return 1;
            }
            //we checked this one so we turn of the respective bit
            candidate_bit_map &= (0xfffe)<<first_on_bit_64(candidate_bit_map);
        }
        //check if the block has empty cells.
        //if there is at least one empty that means it was never inserted
        if (get_bit_map(ducktable->blocks + (hb + i)%pow2(ducktable->hash_bits), BLOCK_EMPTY)) {
            return 0;
        }
    }
    return 0;
}

int ducktable_retrieve(ducktable_t *restrict ducktable,const char *restrict key, void *restrict data)
{
    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;

    if (!ducktable || !key || !data) return -1;

    hash_val = hash(key, ducktable->key_size);
    hs = get_hs(hash_val);
    hb = get_hb(hash_val, ducktable->hash_bits);

    //for every block
    for (uint64_t i = 0; i < pow2(ducktable->hash_bits); i++) {
        //create the bit map
        candidate_bit_map = get_bit_map(ducktable->blocks + hb + i, hs);

        //check every matching item in the block
        while (candidate_bit_map != 0) {
            if (memcmp(key,
                ducktable->data +
                (((hb + i)%pow2(ducktable->hash_bits)) * BLOCK_SIZE /*move to the block*/
                +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                *(ducktable->data_size) + ducktable->key_offset,
                ducktable->key_size) == 0)
            {
                //copy the data part to return it to the user
                memcpy(data,
                   ducktable->data +
                       (((hb + i)%pow2(ducktable->hash_bits))*BLOCK_SIZE +first_on_bit_64(candidate_bit_map))
                       *(ducktable->data_size),
                       ducktable->data_size);
                return 1;
            }
            //we checked this one so we turn of the respective bit
            candidate_bit_map &= (0xfffe)<<first_on_bit_64(candidate_bit_map);
        }
        //check if the block has empty cells.
        //if there is at least one empty that means it was never inserted
        if (get_bit_map(ducktable->blocks + (hb + i)%pow2(ducktable->hash_bits), BLOCK_EMPTY)) {
            return 0;
        }
    }
    return 0;
}
int ducktable_access(ducktable_t *restrict ducktable,const char *restrict key, void **data)
{
    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;

    if (!ducktable || !key) return -1;

    hash_val = hash(key, ducktable->key_size);
    hs = get_hs(hash_val);
    hb = get_hb(hash_val, ducktable->hash_bits);

    //for every block
    for (uint64_t i = 0; i < pow2(ducktable->hash_bits); i++) {
        //create the bit map
        candidate_bit_map = get_bit_map(ducktable->blocks + hb + i, hs);

        //check every matching item in the block
        while (candidate_bit_map != 0) {
            if (memcmp(key,
                ducktable->data +
                (((hb + i)%pow2(ducktable->hash_bits))*BLOCK_SIZE /*move to the block*/
                +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                *(ducktable->data_size),
                ducktable->key_size) == 0)
            {
                *data = ducktable->data +
                       (((hb + i)%pow2(ducktable->hash_bits))*BLOCK_SIZE +first_on_bit_64(candidate_bit_map))
                       *(ducktable->data_size);
                return 1;
            }
            //we checked this one so we turn of the respective bit
            candidate_bit_map &= (0xfffe)<<first_on_bit_64(candidate_bit_map);
        }
        //check if the block has empty cells.
        //if there is at least one empty that means it was never inserted
        if (get_bit_map(ducktable->blocks + (hb + i)%pow2(ducktable->hash_bits), BLOCK_EMPTY)) {
            return 0;
        }
    }
    return 0;
}

int ducktable_insert(ducktable_t *const restrict ducktable,const char *restrict const key,const char *restrict const data)
{
    if (!ducktable || !key || !data) return -1;

    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;

    if (!ducktable || !key) return -1;

    //check if we need to resize
    if ( ducktable->bucket_count+1 > pow2(ducktable->hash_bits)/(ducktable->data_size) ) {
        // we need to resize
        const int ret = expand_ducktable(ducktable);
        if (ret != 0) {
            return ret;
        }
    }

    hash_val = hash(key, ducktable->key_size);
    hs = get_hs(hash_val);
    hb = get_hb(hash_val, ducktable->hash_bits);

    //do a modified search
    for (uint64_t i = 0; i < pow2(ducktable->hash_bits); i++) {
        //create the bit map
        candidate_bit_map = get_bit_map(ducktable->blocks + (hb + i)%pow2(ducktable->hash_bits), hs);
        while (candidate_bit_map != 0) {
            if (memcmp(key,
                ducktable->data +
                (((hb + i)%pow2(ducktable->hash_bits))*BLOCK_SIZE /* move to the block*/
                +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                *(ducktable->data_size) + ducktable->key_offset, /*times the size of a bucket*/
                ducktable->key_size) == 0)
            {
                return 1;
            }

            //we checked this one so we turn of the respective bit
            candidate_bit_map &= (0xfffe)<<first_on_bit_64(candidate_bit_map);
        }
        //check if the block has empty cells.
        //if there is at least one empty that means it was never inserted
        if (get_bit_map(ducktable->blocks + (hb + i)%pow2(ducktable->hash_bits), BLOCK_EMPTY)) {
            // we found an empty slot thus we insert it here
            const char idx = first_on_bit_64(~candidate_bit_map);
            //(hb + i)%pow2(ducktable->hash_bits) + idx
            //TRANSLATION:
            //(hb + i)%pow2(ducktable->hash_bits) is the block we found free
            //idx is the index inside the block [0,15]

            memcpy(ducktable->data
                +(((hb + i)%pow2(ducktable->hash_bits))*BLOCK_SIZE + idx)*(ducktable->data_size)
                ,data,ducktable->data_size);

            ducktable->blocks[(hb + i)%pow2(ducktable->hash_bits)].block_bytes[idx] = hs;

            ++(ducktable->bucket_count);
            return 0;
        }
    }

    return 0;
}

int ducktable_remove(ducktable_t *const restrict ducktable,const char *restrict const key)
{
    uint64_t hash_val;
    char hs;
    uint64_t hb;
    uint16_t candidate_bit_map = 0;

    if (!ducktable || !key) return -1;

    hash_val = hash(key, ducktable->key_size);
    hs = get_hs(hash_val);
    hb = get_hb(hash_val, ducktable->hash_bits);

    //for every block
    for (uint64_t i = 0; i < pow2(ducktable->hash_bits); i++) {
        //create the bit map
        candidate_bit_map = get_bit_map(ducktable->blocks + hb + i, hs);

        //check every matching item in the block
        while (candidate_bit_map != 0) {
            if (memcmp(key,
                ducktable->data +
                (((hb + i)%pow2(ducktable->hash_bits))*BLOCK_SIZE /*move to the block*/
                +first_on_bit_64(candidate_bit_map)) /*move to the elements in the block*/
                *(ducktable->data_size) + ducktable->key_offset,
                ducktable->key_size) == 0)
            {
                //just edit the block. You dont need to erase data
                ducktable->blocks[(hb + i)%pow2(ducktable->hash_bits)]
                .block_bytes[first_on_bit_64(candidate_bit_map)]= BLOCK_DEAD;
                --(ducktable->bucket_count);
                return 0;
            }
            //we checked this one so we turn of the respective bit
            candidate_bit_map &= (0xfffe)<<first_on_bit_64(candidate_bit_map);
        }
        //check if the block has empty cells.
        //if there is at least one empty that means it was never inserted
        if (get_bit_map(ducktable->blocks + (hb + i)%pow2(ducktable->hash_bits), BLOCK_EMPTY)) {
            return 1;
        }
    }
    return 1;

}

void ducktable_lock(ducktable_t *restrict ducktable)
{
    if (!ducktable) return;
    pthread_mutex_lock(&ducktable->mutex);
}
void ducktable_unlock(ducktable_t *restrict ducktable)
{
    if (!ducktable) return;
    pthread_mutex_unlock(&ducktable->mutex);
}

int ducktable_rehash(ducktable_t *ducktable)
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

    //allocate new data array and re-hash the whole table
    new_table = malloc(pow2(ducktable->hash_bits) * (ducktable->data_size));
    new_blocks = malloc(pow2(ducktable->hash_bits));
    key = malloc(ducktable->key_size);
    if (!new_table || !new_blocks || !key) {
        free(new_table);
        free(new_blocks);
        free(key);
        return -1;
    }

    //initialize the blocks
    //slow if we can use vectors
    for (uint64_t i = 0; i < pow2(ducktable->hash_bits)*(BLOCK_SIZE/sizeof(empty_block)); i++) {
        memcpy(((unsigned char *)new_blocks) + i*sizeof(empty_block), &empty_block, sizeof(empty_block));
    }

    //we need to insert every key and data pair to the new table

    //for every old block
    for (uint64_t i = 0; i < pow2(ducktable->hash_bits - 1); i++) {
        //find the cells that are not empty and not removed elements
        //thus the cells that hold an element
        occupied_bit_map = get_bit_map(ducktable->blocks + i,BLOCK_EMPTY);
        occupied_bit_map += get_bit_map(ducktable->blocks + i,BLOCK_DEAD);
        occupied_bit_map = ~occupied_bit_map;

        while (occupied_bit_map != 0) {
            memcpy(key,
                  ducktable->data
                   + (i*BLOCK_SIZE + first_on_bit_64(occupied_bit_map)) * (ducktable->data_size) + ducktable->key_offset,
                   ducktable->key_size);

            //do a modified insert
            //hash the key
            hash_val = hash(key, ducktable->key_size);
            hs = get_hs(hash_val);
            hb = get_hb(hash_val, ducktable->hash_bits);

            //for every block in the new table
            for (uint64_t k = 0; k < pow2(ducktable->hash_bits); k++) {
                //check if the block has empty cells.
                candidate_bit_map = get_bit_map(ducktable->blocks + (hb + k)%pow2(ducktable->hash_bits), BLOCK_EMPTY);
                if (candidate_bit_map) {
                    // we found an empty slot thus we insert it here
                    const char idx = first_on_bit_64(candidate_bit_map);
                    //(hb/16 +16*i + idx
                    //TRANSLATION:
                    //hb/16 is the 16 item block possession
                    //16*i is how many block away from the original block we found an empty spot
                    //idx is the index inside the block [0,15]
                    memcpy(new_table + (((hb + k)%pow2(ducktable->hash_bits))*BLOCK_SIZE + idx)*(ducktable->data_size),
                           ducktable->data + (i*BLOCK_SIZE + first_on_bit_64(occupied_bit_map))*(ducktable->data_size),
                           ducktable->data_size);

                    new_blocks[(hb + k)%pow2(ducktable->hash_bits)].block_bytes[idx] = hs;

                    //we checked this one so we turn of the respective bit
                    occupied_bit_map &= (0xfffe)<<first_on_bit_64(occupied_bit_map);
                    break;
                }
            }
        }
    }
    free(key);
    //reuse key as a temporary pointer
    key = ducktable->blocks;
    ducktable->blocks = new_blocks;
    free(key);
    key = ducktable->data;
    ducktable->data = new_table;
    free(key);

    return 0;
}