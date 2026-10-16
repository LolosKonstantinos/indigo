add_library(queue SHARED queue.c)

target_link_libraries(queue PUBLIC queue_includes tp_logger)