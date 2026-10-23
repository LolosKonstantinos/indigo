add_library(plugin_includes INTERFACE  indigo_plugin.h indigo_plugin_interface.h)


target_include_directories(plugin_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})