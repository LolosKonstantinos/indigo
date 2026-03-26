//
// Created by Κωνσταντίνος on 4/16/2025.
//
//todo-> define the error codes after the system is completed
#ifndef INDIGO_DEVICE_DISCOVERY_H
#define INDIGO_DEVICE_DISCOVERY_H


#define ON 1
#define OFF 0


// #define SIGNATURE_REQUEST_PROCESSING_RATE 1 //1 request per second
// #define SIGNATURE_REQUEST_MAX_PER_IP_INTERVAL 6


//for now, it's ok, later we will need to add linux libraries
#ifdef _WIN32

#include <winsock2.h>

#endif

#include <pthread.h>


#endif //INDIGO_DEVICE_DISCOVERY_H
