add_library(queue SHARED Queue.c)

target_link_libraries(queue PUBLIC queue_includes)