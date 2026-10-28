add_library(diplomat SHARED diplomat.c)

target_link_libraries(diplomat PUBLIC diplomat_includes)