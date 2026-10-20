add_library(plugin_includes INTERFACE  plugin.h)

target_include_directories(plugin_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})