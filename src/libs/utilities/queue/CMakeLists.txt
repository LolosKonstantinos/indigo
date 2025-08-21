add_library(queue SHARED Queue.c
        ../../../../include/indigo_errors.h)

target_link_libraries(queue PUBLIC queue_includes)