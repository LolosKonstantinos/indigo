add_library(cli SHARED cli.c)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0)

target_link_libraries(cli PUBLIC cli_includes indigo_types)
target_link_libraries(cli PRIVATE crypto_utils kernel32 sodium queue PkgConfig::GLIB )