add_library(set SHARED set.c)

target_link_libraries(set PUBLIC set_includes tp_logger)