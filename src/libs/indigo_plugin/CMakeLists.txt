add_library(indigo_plugin SHARED indigo_plugin.c)

target_link_libraries(indigo_plugin PUBLIC plugin_includes)
target_link_libraries(indigo_plugin PRIVATE dl config PkgConfig::GLIB)