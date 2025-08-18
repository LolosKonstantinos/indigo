add_library(path SHARED path.c)

target_link_libraries(path PUBLIC path_includes)