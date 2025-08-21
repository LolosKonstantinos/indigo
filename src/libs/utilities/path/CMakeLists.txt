add_library(path SHARED path.c
        ../../../../include/indigo_errors.h)

target_link_libraries(path PUBLIC path_includes)