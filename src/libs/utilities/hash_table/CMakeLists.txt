add_library(hash_table SHARED hash_table.c)

target_link_libraries(hash_table PUBLIC hash_table_includes)