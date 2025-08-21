add_library(event_flags SHARED event_flags.c
        ../../../../include/indigo_errors.h)

target_link_libraries(event_flags PUBLIC event_flag_includes)