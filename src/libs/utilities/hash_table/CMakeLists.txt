add_library(hash_table SHARED hash_functions.c hash_table.c)
add_library(lht SHARED lht.c hash_functions.c)
add_library(dpht SHARED dpht.c hash_functions.c)

target_link_libraries(hash_table PUBLIC hash_table_includes)
target_link_libraries(lht PUBLIC hash_table_includes)
target_link_libraries(dpht PUBLIC hash_table_includes)