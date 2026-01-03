//
// Created by Constantin on 02/01/2026.
//
#include "hash_table.h"

struct dynamic_perfect_hash_table_priv {
    hashFunction hash;
    first_level_ht_node *hash_table;
    size_t cell_count;
    size_t cell_size;
    size_t bucket_count;                //the total amount of elements stored
    uint8_t hash_bit_length;
    uint32_t key_length;
};



/*__________________________________________________HASH_FUNCTIONS____________________________________________________*/
unsigned int MurMurHash(const char *str, unsigned int length) {
    uint32_t hash;

    MurmurHash3_x86_32(str, length, 0x7FFFFFFF, &hash);
    return hash;
}

unsigned int FastHash(const char *str, unsigned int length) {
    uint64_t hash = fasthash64(str,length,0x7FFFFFFF);
    return hash - (hash >> 32);
}

//fasthash

#define mix(h) ({					\
(h) ^= (h) >> 23;		\
(h) *= 0x2127599bf4325c37ULL;	\
(h) ^= (h) >> 47; })

uint64_t fasthash64(const void *buf, size_t len, uint64_t seed)
{
    const uint64_t    m = 0x880355f21e6d1965ULL;
    const uint64_t *pos = (const uint64_t *)buf;
    const uint64_t *end = pos + (len / 8);
    const unsigned char *pos2;
    uint64_t h = seed ^ (len * m);
    uint64_t v;

    while (pos != end) {
        v  = *pos++;
        h ^= mix(v);
        h *= m;
    }

    pos2 = (const unsigned char*)pos;
    v = 0;

    switch (len & 7) {
    case 7: v ^= (uint64_t)pos2[6] << 48;
    case 6: v ^= (uint64_t)pos2[5] << 40;
    case 5: v ^= (uint64_t)pos2[4] << 32;
    case 4: v ^= (uint64_t)pos2[3] << 24;
    case 3: v ^= (uint64_t)pos2[2] << 16;
    case 2: v ^= (uint64_t)pos2[1] << 8;
    case 1: v ^= (uint64_t)pos2[0];
        h ^= mix(v);
        h *= m;
    }

    return mix(h);
}


#define	FORCE_INLINE inline __attribute__((always_inline))

inline uint32_t rotl32 ( uint32_t x, int8_t r )
{
    return (x << r) | (x >> (32 - r));
}

inline uint64_t rotl64 ( uint64_t x, int8_t r )
{
    return (x << r) | (x >> (64 - r));
}

#define	ROTL32(x,y)	rotl32(x,y)
#define ROTL64(x,y)	rotl64(x,y)

#define BIG_CONSTANT(x) (x##LLU)

FORCE_INLINE uint32_t getblock32 ( const uint32_t * p, int i )
{
    return p[i];
}

FORCE_INLINE uint64_t getblock64 ( const uint64_t * p, int i )
{
    return p[i];
}

FORCE_INLINE uint32_t fmix32 ( uint32_t h )
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}

//----------

FORCE_INLINE uint64_t fmix64 ( uint64_t k )
{
    k ^= k >> 33;
    k *= BIG_CONSTANT(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;

    return k;
}



void MurmurHash3_x86_32 ( const void * key, int len,
                          uint32_t seed, void * out )
{
    const uint8_t * data = (const uint8_t*)key;
    const int nblocks = len / 4;

    uint32_t h1 = seed;

    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    //----------
    // body

    const uint32_t * blocks = (const uint32_t *)(data + nblocks*4);

    for(int i = -nblocks; i; i++)
    {
        uint32_t k1 = getblock32(blocks,i);

        k1 *= c1;
        k1 = ROTL32(k1,15);
        k1 *= c2;

        h1 ^= k1;
        h1 = ROTL32(h1,13);
        h1 = h1*5+0xe6546b64;
    }

    //----------
    // tail

    const uint8_t * tail = (const uint8_t*)(data + nblocks*4);

    uint32_t k1 = 0;

    switch(len & 3)
    {
    case 3: k1 ^= tail[2] << 16;
    case 2: k1 ^= tail[1] << 8;
    case 1: k1 ^= tail[0];
        k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
    };

    //----------
    // finalization

    h1 ^= len;

    h1 = fmix32(h1);

    *(uint32_t*)out = h1;
}