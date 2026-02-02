//
// Created by Constantin on 10/08/2025.
//

#ifndef SESSION_H
#define SESSION_H

#define TCP_PORT 4363 //the only reason I keep it, is because I don't wanna re-check which ports are "available"
#define SESSION_MAX_RETRIES 4

#define SESSION_MAGIC_NUMBER 3317179837
#define SESSION_PACKET_SIZE (86 + crypto_sign_BYTES)
#define SESSION_ID_BYTES 32
#include <pthread.h>
#include <stdint.h>
#include "crypto_utils.h"
#include  <sodium.h>

#endif //SESSION_H
