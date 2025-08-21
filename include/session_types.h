//
// Created by Constantin on 19/08/2025.
//

#ifndef SESSION_TYPES_H
#define SESSION_TYPES_H
#include <stdint.h>
#include <sodium/crypto_sign.h>

#define SESSION_MAGIC_NUMBER 3317179837
#define SESSION_PACKET_SIZE (86 + crypto_sign_BYTES)
#define SESSION_ID_BYTES 16

typedef enum session_msg_type {
    seserr = 0,
    sesinit = 1,
    sesdecline,
    seswait,
    sesstop,
    sesping,
    sespong,
    sesrepeat,
    seskey,
    sesnonce,
    sessigned_key,
    sessigned_nonce
}SESSION_MSG_TYPE;


struct session_msg {
    uint32_t magic_number;
    unsigned char session_id[SESSION_ID_BYTES];
    SESSION_MSG_TYPE type;
    unsigned char zero[64 + crypto_sign_BYTES];
};

typedef struct session_msg SESSION_MSG,
                           SESSION_INIT,
                           SESSION_DECLINE,
                           SESSION_WAIT,
                           SESSION_STOP,
                           SESSION_PING,
                           SESSION_PONG,
                           SESSION_REPEAT;

struct session_key {
    uint32_t magic_number;
    unsigned char session_id[SESSION_ID_BYTES];
    uint16_t type;
    unsigned char key[32];
    unsigned char zero[32 + crypto_sign_BYTES];
};


typedef struct session_key SESSION_KEY;

struct session_nonce {
    uint32_t magic_number;
    unsigned char session_id[SESSION_ID_BYTES];
    uint16_t type;
    unsigned char nonce[64];
    unsigned char zero[crypto_sign_BYTES];
};

typedef struct session_nonce SESSION_NONCE;

struct session_signed_key {
    uint32_t magic_number;
    unsigned char session_id[SESSION_ID_BYTES];
    uint16_t type;
    unsigned char key[32 + crypto_sign_BYTES];
    unsigned char zero[32];
};

typedef struct session_signed_key SESSION_SIGNED_KEY;

struct session_signed_nonce {
    uint32_t magic_number;
    unsigned char session_id[SESSION_ID_BYTES];
    uint16_t type;
    unsigned char nonce[64 + crypto_sign_BYTES];
};

typedef struct session_signed_nonce SESSION_SIGNED_NONCE;

#endif //SESSION_TYPES_H
