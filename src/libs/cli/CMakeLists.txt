add_library(cli SHARED cli.c)

target_link_libraries(cli PUBLIC cli_includes)
target_link_libraries(cli PRIVATE crypto_utils kernel32)