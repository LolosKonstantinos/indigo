add_library(logger SHARED logger.c)

target_link_libraries(logger PUBLIC logger_includes tp_logger)