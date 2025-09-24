add_library(mempool SHARED mempool.c)

target_link_libraries(mempool PUBLIC mempool_includes)