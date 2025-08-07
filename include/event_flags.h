//
// Created by Constantin on 07/08/2025.
//

#ifndef EVENT_FLAGS_H
#define EVENT_FLAGS_H

#include <pthread.h>
#include <stdint.h>

#define EF_ERROR 0x00000001
#define EF_INTERFACE_UPDATE 0x00000002
#define EF_SEND_MULTIPLE_PACKETS 0x00000004
#define EF_NEW_DEVICE 0x00000008
#define EF_TERMINATION 0x00000010
#define EF_OVERRIDE_IO 0x00000020
#define EF_WAKE_MANAGER 0x00000040

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
void wait_on_flag_condition(EFLAG *flag, uint32_t flag_value, uint8_t status);

#endif //EVENT_FLAGS_H
