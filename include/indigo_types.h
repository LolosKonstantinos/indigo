/*Copyright (c) 2026 Lolos Konstantinos

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

#ifndef INDIGO_TYPES_H
#define INDIGO_TYPES_H

#ifdef _WIN32
#include <winsock2.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_kx.h>

/*GLOBAL DEFINITIONS*/
#define FORCE_INLINE inline __attribute__((always_inline))
#define PACKED __attribute__((__packed__))
#define MAX_PSW_LEN 128
#define MAX_USERNAME_LEN 32
#define INDIGO_NONCE_SIZE 32

#define ON 1
#define OFF 0

#define INDIGO_CRYPTO_DIR               "config/crypto/"
#define INDIGO_PSW_DIR                  "config/crypto/psw/"
#define INDIGO_KEY_DIR                  "config/crypto/key/"
#define INDIGO_SIGN_KEY_FILE_NAME       "sign.dat"
#define INDIGO_PSW_HASH_FILE_NAME       "psw-hash.txt"
#define INDIGO_PSW_HASH_SETTINGS_FILE   "psw-hash-settings.dat"
#define INDIGO_KNOWN_KEYS_FILE_NAME     "known-keys.dat" //todo use database (sqlite3)
#define INDIGO_PROGRAM_DATA_DIR         "data"
#define INDIGO_USER_DIR                 "config/user/"
#define INDIGO_USERNAME_FILE_NAME       "username.txt"
#define INDIGO_SETTINGS_DIR             "config/settings/"
#define INDIGO_SETTINGS_FILE_NAME       "settings.config"


//RDSF == RemoteDeviceStateFlag
#define RDSF_UNVERIFIED     0x0000
#define RDSF_VERIFIED       0x0001

#define PAC_VERSION (1)
#define DISCOVERY_SEND_PERIOD_SEC (10)

#define PAC_DATA_PAYLOAD_BYTES (1<<10)
#define PAC_DATA_BYTES_USABLE (PAC_DATA_PAYLOAD_BYTES + (sizeof(uint64_t)<<1)) // 1KiB payload + 2 64bit ints
#define PAC_DATA_BYTES (PAC_DATA_BYTES_USABLE + crypto_aead_xchacha20poly1305_ietf_ABYTES)
#define PAC_MIN_BYTES (sizeof(udp_packet_header_t))
#define PAC_ENCRYPT_OFFSET (offsetof(packet_t, zero))
#define PAC_ENCRYPT_BYTES (PAC_DATA_BYTES_USABLE + 4)
#define PAC_MAX_BYTES (sizeof(packet_t))

//message types
#define MSG_INIT_PACKET                 0x01
#define MSG_RESEND                      0x02
#define MSG_SIGNING_REQUEST             0x03
#define MSG_SIGNING_RESPONSE            0x04
#define MSG_FILE_SENDING_REQUEST        0x05
#define MSG_FILE_SENDING_RESPONSE       0x06
#define MSG_FILE_CHUNK                  0x07
#define MSG_STOP_FILE_TRANSMISSION      0x08
#define MSG_PAUSE_FILE_TRANSMISSION     0x09
#define MSG_CONTINUE_FILE_TRANSMISSION  0x0a
#define MSG_IP_CHANGE                   0x0b
#define MSG_ERR                         0xff
//more types may be added

//the packet that is sent for everything, device discovery, signature handshakes, file chunks, etc.
//it's a little big but since the buffer is at the end there is no need to send the whole thing
typedef struct PACKED udp_packet_t{
    uint32_t magic_number;
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    int16_t zero;
    unsigned char pac_type;
    unsigned char pac_version;
    unsigned char data[PAC_DATA_BYTES];
}packet_t;
_Static_assert(sizeof(packet_t) == 1120, "unexpected padding in packet_t");

typedef struct PACKED udp_packet_header {
    uint32_t magic_number;
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    int16_t zero;
    unsigned char pac_type;
    unsigned char pac_version;
}udp_packet_header_t;

//for device discovery system and queue
typedef struct packet_info_t {
    struct sockaddr_in address;
    SOCKET socket;
}packet_info_t;

//the discovery packet format

typedef struct PACKED init_packet_data_t {
    time_t timestamp;
    wchar_t username[MAX_USERNAME_LEN];
    unsigned char signature[crypto_sign_BYTES];
}init_packet_data_t;
#define PAC_INIT_SIZE (sizeof(udp_packet_header) + sizeof(init_packet_data_t))

typedef struct PACKED signing_request_data_t {
    time_t timestamp;
    unsigned char nonce[INDIGO_NONCE_SIZE];
    unsigned char signature[crypto_sign_BYTES];
}signing_request_data_t;
#define PAC_SIGNING_REQUEST_SIZE (sizeof(udp_packet_header) + sizeof(signing_request_data_t))

typedef struct PACKED signing_response_data_t {
    unsigned char signed_nonce[INDIGO_NONCE_SIZE + crypto_sign_BYTES];
    unsigned char pkx[crypto_kx_PUBLICKEYBYTES];
    unsigned char sig_request;
    unsigned char zero; //odd bytes eww
    unsigned char nonce[INDIGO_NONCE_SIZE];
    unsigned char signature[crypto_sign_BYTES];
}signing_response_data_t;
#define PAC_SIGNING_RESPONSE (sizeof(udp_packet_header) + sizeof(signing_response_data_t))

typedef struct PACKED file_sending_request_data_t {
    uint64_t serial;
    size_t file_size;
    wchar_t file_name[MAX_PATH];
}file_sending_request_data_t;
#define PAC_FILE_SENDING_REQUEST_SIZE (sizeof(udp_packet_header) +sizeof(file_sending_request_data_t))

typedef struct PACKED file_sending_response_data_t {
    uint64_t serial;
}file_sending_response_data_t;
#define FILE_SENDING_RESPONSE_SIZE (sizeof(udp_packet_header) + sizeof(file_sending_response_data_t))

typedef struct PACKED file_chunk_data_t {
    uint64_t serial;
    uint64_t chunk_number;
    unsigned char data[PAC_DATA_PAYLOAD_BYTES];
}file_chunk_data_t;
#define PAC_FILE_CHUNK_SIZE (sizeof(udp_packet_header) + sizeof(file_chunk_data_t))

typedef struct PACKED transmission_control_data_t {
    uint64_t serial;
    uint64_t first_packet_number; //used only for resend, otherwise should be 0 and ignored
    uint64_t last_packet_number;  //the end of the range, if we need a range of packets to be resent
}transmission_control_data_t;
#define PAC_TRANSMISSION_CONTROL_SIZE (sizeof(udp_packet_header) + sizeof(transmission_control_data_t))

typedef struct remote_device_t{
    time_t expiration_time; //the time until which we consider the device active, updated with any packet
    uint64_t last_fid;
    int port;
    uint32_t ip;
    unsigned char peer_pk[crypto_sign_PUBLICKEYBYTES];

    unsigned char *client_rk;
    unsigned char *client_tk;
    unsigned char *server_rk;
    unsigned char *server_tk;

    wchar_t username[MAX_USERNAME_LEN];
    uint16_t dev_state_flag;
} remote_device_t;

typedef struct session_id_t {
    uint64_t serial;
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
}session_id_t;

typedef struct session_t{
    session_id_t session_id;
    int port;
    uint32_t ip;
    time_t start_time;
    time_t end_time;
    size_t bytes_moved;
    uint16_t status_flags;
} session_t;

typedef struct active_file_t {
    struct active_file_t *next;
    FILE *fd;
    uint64_t counter;
    session_id_t session_id;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char *tk;
    int port;
    uint32_t ip;
}active_file_t;






/*inline function definitions*/
static FORCE_INLINE int cmp_rdev(void *s1, void *s2) {
    return memcmp(((remote_device_t *)s1)->peer_pk, ((remote_device_t *)s2)->peer_pk, crypto_sign_PUBLICKEYBYTES);
}

#endif //INDIGO_TYPES_H