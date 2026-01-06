//
// Created by Constantin on 10/08/2025.
//

#include "session.h"
#include"indigo_errors.h"

//a session object is to be used after a session is initiated to send and receive files

struct SESSION{
    SOCKET *socket;
    int port;
    uint32_t ip;
    unsigned char mac_addr[6];
    unsigned char peer_public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char session_symmetric_key[crypto_kx_SESSIONKEYBYTES];
    pthread_t tid;
    time_t start_time;
    time_t end_time;
    size_t bytes_sent;
    size_t bytes_received;
    uint8_t status_flags;
};

#define SESSION_SOCKET 0x01
#define SESSION_PORT 0x02
#define SESSION_IP 0x03
#define SESSION_MAC 0x04
#define SESSION_PEER_PUBKEY 0x05
#define SESSION_SESSION_SYMMETRIC_KEY 0x06
#define SESSION_TID 0x07
#define SESSION_START_TIME 0x08
#define SESSION_END_TIME 0x09
#define SESSION_BYTES_SENT 0x0A
#define SESSION_BYTES_RECEIVED 0x0B
#define SESSION_STATUS_FLAG 0x0C

#define SESSION_PHASE_1 0x00
#define SESSION_PHASE_2 0x01
#define SESSION_PHASE_3 0x02
#define SESSION_PHASE_4 0x04
#define SESSION_PHASE_5 0x08

SESSION *session_new() {
    SESSION *session = sodium_malloc(sizeof(SESSION));
    if (session == NULL) {
        return NULL;
    }
    memset(session, 0, sizeof(SESSION)); //todo use sodium's zero memory function
    return session;
}

void session_destroy(SESSION *session) {
    sodium_free(session);
}

int init_session(int port, uint32_t address,SESSION *session) {
    unsigned char *public_key = NULL;
    unsigned char *secret_key = NULL;
    unsigned char *symmetric_key = NULL;

    int ret;

    if (session == NULL) return INDIGO_ERROR_INVALID_PARAM;

//generate the session keys
    public_key = sodium_malloc(crypto_box_PUBLICKEYBYTES);
    if (public_key == NULL) return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    secret_key = sodium_malloc(crypto_box_SECRETKEYBYTES);
    if (secret_key == NULL) {
        sodium_free(public_key);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    ret = crypto_box_keypair(public_key, secret_key);
    if (ret != 0) {
        sodium_free(public_key);
        sodium_free(secret_key);
        return INDIGO_ERROR_SODIUM_ERROR;
    }

    return INDIGO_SUCCESS;
}

int session_set(SESSION *session, uint16_t field, void *value, size_t size) {
    if (session == NULL || value == NULL || size == 0) return INDIGO_ERROR_INVALID_PARAM;
    switch (field) {
        case SESSION_SOCKET:
            if (size != sizeof(SOCKET *)) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->socket, value, size);
            break;
        case SESSION_PORT:
            if (size != sizeof(int)) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->port, value, size);
            break;
        case SESSION_IP:
            if (size != sizeof(uint32_t)) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->ip, value, size);
            break;
        case SESSION_MAC:
            if (size != 6) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->mac_addr, value, size);
            break;
        case SESSION_PEER_PUBKEY:
            if (size != crypto_box_PUBLICKEYBYTES) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->peer_public_key, value, size);
            break;
        case SESSION_SESSION_SYMMETRIC_KEY:
            if (size != crypto_kx_SESSIONKEYBYTES) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->session_symmetric_key, value, size);
            break;
        case SESSION_TID:
            if (size != sizeof(pthread_t)) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->tid, value, size);
            break;
        case SESSION_START_TIME:
            if (size != sizeof(time_t)) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->start_time, value, size);
            break;
        case SESSION_END_TIME:
            if (size != sizeof(time_t)) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->end_time, value, size);
            break;
        case SESSION_BYTES_SENT:
            if (size != sizeof(size_t)) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->bytes_sent, value, size);
            break;
        case SESSION_BYTES_RECEIVED:
            if (size != sizeof(size_t)) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->bytes_received, value, size);
            break;
        case SESSION_STATUS_FLAG:
            if (size != sizeof(uint8_t)) return INDIGO_ERROR_INVALID_PARAM;
            memcpy(&session->status_flags, value, size);
            break;
        default:
            return INDIGO_ERROR_INVALID_PARAM;
    }
    return INDIGO_SUCCESS;
}

int exchange_public_keys(unsigned char public_key[crypto_box_PUBLICKEYBYTES],
                        SIGNING_KEY_PAIR *key_pair,
                        unsigned char peer_key[crypto_box_PUBLICKEYBYTES]) {
    /*METHOD:
     * 1)use UDP
     * 2)send plain message to initiate session
     * 3)wait for plain response
     * 4)send signing key public key
     * 5)wait for peer to send random string
     * 6)sign the string and send
     * 7)wait for peer key
     * 8)send random string
     * 9)wait for signed string
     * 10)verify the string
     * 11)send ephemeral key (signed)
     * 12)wait for peer ephemeral key
     */
    return INDIGO_SUCCESS;
}

int send_key_exchange_packet(const SOCKET *sock,const uint32_t addr,const int port,const void *const packet) {
    WSABUF buf;
    DWORD bytes;
    int tolen;
    struct sockaddr_in to = {0};
    OVERLAPPED overlapped;
    int ret;
    DWORD wait_ret;


    buf.buf = malloc(SESSION_PACKET_SIZE);
    if (buf.buf == NULL) {
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    memcpy(buf.buf, packet, SESSION_PACKET_SIZE);
    buf.len = SESSION_PACKET_SIZE;

    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL) {
        free(buf.buf);
        return INDIGO_ERROR_WINLIB_ERROR;
    }

    to.sin_addr.S_un.S_addr = addr;
    to.sin_family = AF_INET;
    to.sin_port = port;
    tolen = sizeof(to);

    ret = WSASendTo(*sock,&buf,1,&bytes,0, (struct sockaddr *)(&to), tolen ,&overlapped,NULL);

    if (ret == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            fprintf(stderr, "WSASendTo() failed in send_discovery_packets(): %d\n",WSAGetLastError());
            free(buf.buf);
            WSACloseEvent(overlapped.hEvent);
            return INDIGO_ERROR_WINLIB_ERROR;
        }
    }

    wait_ret = WaitForSingleObject(overlapped.hEvent, 100);

    if (wait_ret != WAIT_OBJECT_0) {
        if (wait_ret == WAIT_TIMEOUT) {
            CancelIo(overlapped.hEvent);
        }
        else if (wait_ret == WAIT_FAILED) {
            fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n", WSAGetLastError());
            free(buf.buf);
            WSACloseEvent(overlapped.hEvent);
            return INDIGO_ERROR_WINLIB_ERROR;
        }
        else {
            fprintf(stderr, "UNKNOWN ERROR IN send_key_exchange_packet\n");
            free(buf.buf);
            WSACloseEvent(overlapped.hEvent);
            return INDIGO_ERROR_WINLIB_ERROR;
        }
    }

    free(buf.buf);
    WSACloseEvent(overlapped.hEvent);
    return INDIGO_SUCCESS;
}


int wait_for_key_exchange_packet(const SOCKET *sock, uint32_t addr, int port, SESSION_MSG_TYPE *type, void **data, size_t *size) {
    WSABUF buf = {0};
    DWORD bytes;
    int fromlen;
    struct sockaddr_in from = {0};
    OVERLAPPED overlapped;
    int ret;
    DWORD wait_ret;

    SESSION_MSG message;
    void *pmsg = &message;


    buf.buf = malloc(SESSION_PACKET_SIZE);
    if (buf.buf == NULL) {
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL) {
        free(buf.buf);
        return INDIGO_ERROR_WINLIB_ERROR;
    }


   for (int i = 0; i < SESSION_MAX_RETRIES; i++ ) {
       ret = WSARecvFrom(*sock, &buf, 1, &bytes, 0, (struct sockaddr*)(&from), &fromlen, &overlapped, NULL);
       if (ret == SOCKET_ERROR) {
           if (WSAGetLastError() != WSA_IO_PENDING) {
               fprintf(stderr, "WSARecvFrom() failed in wait_for_key_exchange_packet(): %d\n", WSAGetLastError());
               free(buf.buf);
               WSACloseEvent(overlapped.hEvent);
               return INDIGO_ERROR_WINLIB_ERROR;
           }
       }

       wait_ret = WaitForSingleObject(overlapped.hEvent,(1<<i) * 1000 );
       if (wait_ret == WAIT_OBJECT_0) break;
       if (wait_ret == WAIT_TIMEOUT) continue;
       if (wait_ret == WAIT_FAILED) {
           free(buf.buf);
           WSACloseEvent(overlapped.hEvent);
           return INDIGO_ERROR_WINLIB_ERROR;
       }
   }
    wait_ret = WaitForSingleObject(overlapped.hEvent, 0);
    if (wait_ret == WAIT_TIMEOUT) {
        free(buf.buf);
        WSACloseEvent(overlapped.hEvent);
        CancelIo(overlapped.hEvent);
        return INDIGO_ERROR_TIMEOUT;
    }
    if (wait_ret == WAIT_FAILED) {
        free(buf.buf);
        WSACloseEvent(overlapped.hEvent);
        return INDIGO_ERROR_WINLIB_ERROR;
    }
    if (wait_ret == WAIT_OBJECT_0) {
        WSACloseEvent(overlapped.hEvent);
        //todo: we received from someone else, need to re-receive
        if (from.sin_addr.S_un.S_addr != addr) {
            free(buf.buf);
            return INDIGO_ERROR_INVALID_PACKET;
        }
        //todo: we received wrong packet
        if (bytes != SESSION_PACKET_SIZE) {
            free(buf.buf);
            return INDIGO_ERROR_INVALID_PACKET;
        }

        memcpy(&message, buf.buf, SESSION_PACKET_SIZE);
        free(buf.buf);
        WSACloseEvent(overlapped.hEvent);

        //todo: we received wrong packet
        if (message.magic_number != SESSION_MAGIC_NUMBER) {
            return INDIGO_ERROR_INVALID_PACKET;
        }

        if (message.type < seskey && message.type > seserr) {
            *type = message.type;
            *data = NULL;
            *size = 0;
        }

        switch (message.type) {
        case seskey:
            *data = malloc(32);
            if (*data == NULL) {
                return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            }
            memcpy(*data,((SESSION_KEY *)pmsg)->key,32);
            *size = 32;
            *type = message.type;
            break;
        case sesnonce:
            *data = malloc(64);
            if (*data == NULL) {
                return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            }
            memcpy(*data,((SESSION_NONCE *)pmsg)->nonce,64);
            *size = 64;
            *type = message.type;
            break;
        case sessigned_key:
            *data = malloc(32 + crypto_sign_BYTES);
            if (*data == NULL) {
                return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            }
            memcpy(*data,((SESSION_SIGNED_KEY *)pmsg)->key,32 + crypto_sign_BYTES);
            *size = 32 + crypto_sign_BYTES;
            *type = message.type;
            break;
        case sessigned_nonce:
            *data = malloc(64 + crypto_sign_BYTES);
            if (*data == NULL) {
                return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            }
            memcpy(*data,((SESSION_SIGNED_NONCE *)pmsg)->nonce,64 + crypto_sign_BYTES);
            *size = 64 + crypto_sign_BYTES;
            *type = message.type;
            break;
        default:
            return INDIGO_ERROR_INVALID_PACKET;//the type is incompatible
        }
    }
    return INDIGO_SUCCESS;
}

int gen_session_id(unsigned char session_id[SESSION_ID_BYTES]) {
    time_t timestamp;
    unsigned char temp_id[SESSION_ID_BYTES];
    uint8_t num = SESSION_ID_BYTES - sizeof(time_t);


    randombytes_buf(temp_id,num);
    timestamp = time(NULL);
    memcpy(&temp_id[num],&timestamp,num);
    return INDIGO_SUCCESS;
}

int session_message_new(void ** msg, uint16_t type, void *data, uint16_t size) {
    *msg = malloc(SESSION_PACKET_SIZE);

    if (*msg == NULL) {
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    if (type < seskey && type > seserr) {
        ((SESSION_MSG *)*msg)->type = type;
        ((SESSION_MSG *)*msg)->magic_number = SESSION_MAGIC_NUMBER;
        sodium_memzero(((SESSION_MSG *)*msg)->zero,128);
    }

    switch (type) {
    case seskey:
        if (size != 32) {
            free(*msg);
            return INDIGO_ERROR_INVALID_PARAM;
        }
        memcpy(((SESSION_KEY *)*msg)->key,data,32);
        ((SESSION_KEY *)*msg)->magic_number = SESSION_MAGIC_NUMBER;
        ((SESSION_KEY *)*msg)->type = type;
        sodium_memzero(((SESSION_KEY *)*msg)->zero,96);
        break;
    case sesnonce:
        if (size != 64) {
            free(*msg);
            return INDIGO_ERROR_INVALID_PARAM;
        }
        memcpy(((SESSION_NONCE *)*msg)->nonce,data,64);
        ((SESSION_NONCE *)*msg)->magic_number = SESSION_MAGIC_NUMBER;
        ((SESSION_NONCE *)*msg)->type = type;
        sodium_memzero(((SESSION_NONCE *)*msg)->zero,64);
        break;
    case sessigned_key:
        if (size != 96) {
            free(*msg);
            return INDIGO_ERROR_INVALID_PARAM;
        }
        memcpy(((SESSION_SIGNED_KEY *)*msg)->key,data,96);
        ((SESSION_SIGNED_KEY *)*msg)->magic_number = SESSION_MAGIC_NUMBER;
        ((SESSION_SIGNED_KEY *)*msg)->type = type;
        sodium_memzero(((SESSION_SIGNED_KEY *)*msg)->zero,32);
        break;
    case sessigned_nonce:
        if (size != 128) {
            free(*msg);
            return INDIGO_ERROR_INVALID_PARAM;
        }
        memcpy(((SESSION_SIGNED_NONCE *)*msg)->nonce,data,128);
        ((SESSION_SIGNED_NONCE *)*msg)->magic_number = SESSION_MAGIC_NUMBER;
        ((SESSION_SIGNED_NONCE *)*msg)->type = type;
        break;
    default:
        return INDIGO_ERROR_INVALID_PACKET;//the type is incompatible
    }
    return INDIGO_SUCCESS;
}