add_library(cli SHARED cli.c)

target_link_libraries(cli PRIVATE cli_includes)