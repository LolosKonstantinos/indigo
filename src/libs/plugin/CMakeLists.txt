add_library(plugin SHARED  plugin.c)

target_link_libraries(plugin PUBLIC plugin_includes)
target_link_libraries(plugin PRIVATE dl)