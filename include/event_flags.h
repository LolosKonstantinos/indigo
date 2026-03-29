//
// Created by Constantin on 07/08/2025.
//

#ifndef EVENT_FLAGS_H
#define EVENT_FLAGS_H

#include <pthread.h>
#include <stdint.h>

#define EF_ERROR                         0x00000001
#define EF_INTERFACE_UPDATE              0x00000002
#define EF_SEND_MULTIPLE_PACKETS         0x00000004
#define EF_NEW_PACKET                    0x00000008
#define EF_TERMINATION                   0x00000010
#define EF_OVERRIDE_IO                   0x00000020
#define EF_WAKE_MANAGER                  0x00000040
#define EF_SIGNATURE_REQUEST             0x00000080
#define EF_SIGNATURE_RESPONSE            0x00000100
#define EF_SEND_NEW_FILE                 0x00000200
#define EF_RESEND_FILE_CHUNK             0x00000400
#define EF_STOP_FILE_TRANSMISSION        0x00000800
#define EF_PAUSE_FILE_TRANSMISSION       0x00001000
#define EF_CONTINUE_FILE_TRANSMISSION    0x00002000
#define EF_RESET_SOCKETS                 0x00004000

//todo: we dont need a mutex, use _Atomic and an event object instead of a condition, we can use the msb as a semaphore
typedef struct EVENT_FLAG {
    volatile uint32_t event_flag;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
}EVENT_FLAG, EFLAG;


//////////////////////////////////////////////////////////////
///                                                        ///
///                  EVENT_FLAG_UTILITIES                  ///
///                                                        ///
//////////////////////////////////////////////////////////////

//to dynamically create an event flag
EFLAG *create_event_flag();
int free_event_flag(EFLAG *event_flag);
//to create stack based event flags (works fine with heap memory but allocation and freeing should be done manually)
int init_event_flag(EFLAG *event_flag);
int destroy_event_flag(EFLAG *event_flag);
//setters getters re-setters
int set_event_flag(EFLAG *event_flag, uint32_t flag_value);
int update_event_flag(EFLAG *event_flag, uint32_t flag_value);
int reset_event_flag(EFLAG *event_flag);
int reset_single_event(EFLAG *event_flag, uint32_t flag_value);
uint32_t get_event_flag(EFLAG *event_flag);
uint8_t termination_is_on(EFLAG *event_flag);
//conditions
void wait_on_flag_condition(EFLAG *flag, uint32_t flag_value, uint32_t status);

#endif //EVENT_FLAGS_H
