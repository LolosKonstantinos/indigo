add_library(tp_logger STATIC log.c log.h)
target_include_directories(tp_logger PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})