add_library(tui SHARED tui.c)

target_link_libraries(tui PUBLIC tui_includes)
target_link_libraries(tui PRIVATE crypto_utils libncursesw)