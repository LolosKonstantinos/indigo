add_library(cli_includes INTERFACE cli.h)

target_include_directories(cli_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})