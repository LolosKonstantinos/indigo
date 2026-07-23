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


#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#define NAME_MAX MAX_PATH
#else
#include <limits.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/socket.h>
#endif
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_sign.h>
#include <stdint.h>
#include <stdio.h>

/*GLOBAL DEFINITIONS*/
#define FORCE_INLINE inline __attribute__((always_inline))
#define PACKED __attribute__((__packed__))
#define MAX_PSW_LEN 128
#define MAX_USERNAME_LEN 32
#define INDIGO_NONCE_SIZE 32
#define MAX_SEND_REQUEST_COUNT 10

#define ON 1
#define OFF 0

#define INDIGO_CONFIG_DIR "config"
#define INDIGO_CRYPTO_DIR "config/crypto"
#define INDIGO_PSW_DIR "config/crypto/psw"
#define INDIGO_KEY_DIR "config/crypto/key"
#define INDIGO_USER_DIR "config/user"
#define INDIGO_PROGRAM_DATA_DIR "data"
#define INDIGO_SETTINGS_DIR "config/settings"
#define INDIGO_TEMP_DIR "data/temp"
#define INDIGO_SIGN_KEY_FILE_NAME "sign.dat"
#define INDIGO_PSW_HASH_FILE_NAME "psw-hash.txt"
#define INDIGO_PSW_HASH_SETTINGS_FILE "psw-hash-settings.dat"
#define INDIGO_KNOWN_KEYS_FILE_NAME "known-keys.dat" // TODO: use database (sqlite3)
#define INDIGO_USERNAME_FILE_NAME "username.txt"
#define INDIGO_SETTINGS_FILE_NAME "settings.conf"
#define INDIGO_LOG_FILE_NAME "log.txt"

// RDSF == RemoteDeviceStateFlag
#define RDSF_UNVERIFIED 0x0001
#define RDSF_VERIFIED 0x0002
// known key status values (can be used in the dev_state_flag)
#define KNOWN_KEY_STATUS_TOO_GOOD 0x0004
#define KNOWN_KEY_STATUS_GOOD 0x0008
#define KNOWN_KEY_STATUS_UNKNOWN 0x0010
#define KNOWN_KEY_STATUS_BAD 0x0020
#define KNOWN_KEY_STATUS_EVIL_AND_SINISTER 0x0040

#define PAC_VERSION (1)
#define DISCOVERY_SEND_PERIOD_SEC (10)

#define PAC_DATA_PAYLOAD_BYTES (1 << 10)
#define PAC_DATA_BYTES_USABLE (PAC_DATA_PAYLOAD_BYTES + (sizeof(uint64_t) << 1)) // 1KiB payload + 2 64bit ints
#define PAC_DATA_BYTES (PAC_DATA_BYTES_USABLE + crypto_aead_xchacha20poly1305_ietf_ABYTES)
#define PAC_MIN_BYTES (sizeof(udp_packet_header_t))
#define PAC_ENCRYPT_OFFSET (offsetof(packet_t, zero))
#define PAC_ENCRYPT_BYTES (PAC_DATA_BYTES_USABLE + 4)
#define PAC_MAX_BYTES (sizeof(packet_t))
#define PAC_ALIGNMENT (8)

// message types
#define MSG_INIT_PACKET 0x01
#define MSG_RESEND 0x02
#define MSG_SIGNING_REQUEST 0x03
#define MSG_SIGNING_RESPONSE 0x04
#define MSG_FILE_SENDING_REQUEST 0x05
#define MSG_FILE_SENDING_RESPONSE 0x06
#define MSG_FILE_CHUNK 0x07
#define MSG_STOP_FILE_TRANSMISSION 0x08
#define MSG_PAUSE_FILE_TRANSMISSION 0x09
#define MSG_CONTINUE_FILE_TRANSMISSION 0x0a
#define MSG_IP_CHANGE 0x0b
#define MSG_ERR 0xff
// more types may be added

typedef uint64_t utf8_char_t;

typedef struct range_t {
    uint64_t start;
    uint64_t end;
} range_t;
typedef struct range_node_t {
    range_t r;
    struct range_node_t *next;
} range_node_t;

static FORCE_INLINE int in_range(range_t *r, uint64_t n)
{
    if (n >= r->start && n <= r->end)
        return 1;
    return 0;
}

// the packet that is sent for everything, device discovery, signature
// handshakes, file chunks, etc. it's a little big but since the buffer is at
// the end there is no need to send the whole thing
typedef struct PACKED udp_packet_t {
    uint32_t magic_number;
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    int16_t zero;
    unsigned char pac_type;
    unsigned char pac_version;
    unsigned char data[PAC_DATA_BYTES];
} packet_t;
_Static_assert(sizeof(packet_t) == 1120, "unexpected padding in packet_t");

typedef struct PACKED udp_packet_header {
    uint32_t magic_number;
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    int16_t zero;
    unsigned char pac_type;
    unsigned char pac_version;
} udp_packet_header_t;

// for device discovery system and queue
typedef struct packet_info_t {
    struct sockaddr_in address;
} packet_info_t;

// the discovery packet format

typedef struct PACKED init_packet_data_t {
    uint64_t timestamp;
    char username[MAX_USERNAME_LEN * sizeof(uint32_t)];
    unsigned char signature[crypto_sign_BYTES];
} init_packet_data_t;
#define PAC_INIT_SIZE (sizeof(udp_packet_header) + sizeof(init_packet_data_t))

typedef struct PACKED signing_request_data_t {
    uint64_t timestamp;
    unsigned char nonce[INDIGO_NONCE_SIZE];
    unsigned char signature[crypto_sign_BYTES];
} signing_request_data_t;
#define PAC_SIGNING_REQUEST_SIZE (sizeof(udp_packet_header) + sizeof(signing_request_data_t))

typedef struct PACKED signing_response_data_t {
    unsigned char signed_nonce[INDIGO_NONCE_SIZE + crypto_sign_BYTES];
    unsigned char pkx[crypto_kx_PUBLICKEYBYTES];
    unsigned char sig_request;
    unsigned char zero; // odd bytes eww
    unsigned char nonce[INDIGO_NONCE_SIZE];
    unsigned char signature[crypto_sign_BYTES];
} signing_response_data_t;
#define PAC_SIGNING_RESPONSE_SIZE (sizeof(udp_packet_header) + sizeof(signing_response_data_t))

typedef struct PACKED file_sending_request_data_t {
    uint64_t serial;
    size_t file_size;
    char file_name[NAME_MAX];
} file_sending_request_data_t;
#define PAC_FILE_SENDING_REQUEST_SIZE (sizeof(udp_packet_header) + sizeof(file_sending_request_data_t))

typedef struct PACKED file_sending_response_data_t {
    uint64_t serial;
} file_sending_response_data_t;
#define FILE_SENDING_RESPONSE_SIZE (sizeof(udp_packet_header) + sizeof(file_sending_response_data_t))

typedef struct PACKED file_chunk_data_t {
    uint64_t serial;
    uint64_t chunk_number;
    unsigned char data[PAC_DATA_PAYLOAD_BYTES];
} file_chunk_data_t;
#define PAC_FILE_CHUNK_SIZE (sizeof(udp_packet_header) + sizeof(file_chunk_data_t))

typedef struct PACKED transmission_control_data_t {
    uint64_t serial;
    range_t range; // used only for resend, otherwise should be 0 and ignored
} transmission_control_data_t;
#define PAC_TRANSMISSION_CONTROL_SIZE (sizeof(udp_packet_header) + sizeof(transmission_control_data_t))

typedef struct fwd_fsr_t {
    uint64_t serial;
    size_t file_size; // the size of the file in bytes
    char file_name[NAME_MAX];
    uint32_t addr;
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    char zero[4];
    uint64_t expiration_time;
    struct fwd_fsr_t *next;
} fwd_fsr_t;

typedef struct remote_device_t {
    uint64_t expiration_time; // the time until which we consider the device active,
                            // updated with any packet
    uint64_t last_fid;
    int port;
    uint32_t ip;
    unsigned char peer_pk[crypto_sign_PUBLICKEYBYTES];

    unsigned char *client_rk;
    unsigned char *client_tk;
    unsigned char *server_rk;
    unsigned char *server_tk;

    char username[MAX_USERNAME_LEN * sizeof(uint32_t)];
    uint32_t dev_state_flag;
    uint32_t fsr_count;
    fwd_fsr_t *fsr_list;
} remote_device_t;

typedef struct session_id_t {
    uint64_t serial;
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
} session_id_t;

typedef struct session_t {
    session_id_t session_id;
    int port;
    uint32_t ip;
    uint64_t start_time;
    uint64_t end_time;
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
} active_file_t;

typedef struct known_key_t {
    unsigned char key[crypto_sign_PUBLICKEYBYTES];
    uint64_t status;
} known_key_t;

typedef struct ui_file_t {
    char name[NAME_MAX];
    session_id_t id;
    char direction;
} ui_file_t;

/*inline function definitions*/
static FORCE_INLINE int cmp_rdev(void *s1, void *s2)
{
    return memcmp(((remote_device_t *)s1)->peer_pk, ((remote_device_t *)s2)->peer_pk, crypto_sign_PUBLICKEYBYTES);
}

static FORCE_INLINE int cmp_ui_file(void *s1, void *s2)
{
    return memcmp(&(((ui_file_t *)s1)->id), &(((ui_file_t *)s2)->id), sizeof(session_id_t));
}
#endif // INDIGO_TYPES_H
