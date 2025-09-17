add_library(simple_buffer SHARED buffer.c)

target_link_libraries(simple_buffer PUBLIC buffer_includes)