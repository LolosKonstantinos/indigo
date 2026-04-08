add_library(config SHARED config.c)

target_link_libraries(config PUBLIC config_includes)