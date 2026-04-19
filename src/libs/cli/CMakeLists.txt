add_library(cli SHARED cli.c)

target_link_libraries(cli PUBLIC cli_includes indigo_types)
target_link_libraries(cli PRIVATE crypto_utils kernel32 sodium)