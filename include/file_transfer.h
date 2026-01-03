//
// Created by Constantin on 10/08/2025.
//

#ifndef FILE_TRANSFER_H
#define FILE_TRANSFER_H

#include <wchar.h>
#include <stdint.h>
#include <path.h>

typedef struct trans_file {
    path path;
    FILE *file;
    size_t size;
    size_t chunk_size;
    size_t chunk_count;
    size_t chunks_moved;
}trans_file;

#endif //FILE_TRANSFER_H
