add_library(indigo_core_includes INTERFACE indigo_core.h manager.h net_io.h packet_handler.h net_monitor.h)

target_include_directories(indigo_core_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})