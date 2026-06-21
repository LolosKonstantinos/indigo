add_library(cli SHARED cli.c)

target_link_libraries(cli PUBLIC cli_includes indigo_types indigo_errors)
target_link_libraries(cli PRIVATE crypto_utils
                                  binary_tree
                                  sodium
                                  queue
                                  PkgConfig::GLIB)

if(WIN32)
  target_link_libraries(cli PRIVATE kernel32)
endif()
