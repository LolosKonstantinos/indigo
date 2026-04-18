add_library(tui SHARED tui.c)

target_link_libraries(tui PRIVATE tui_includes crypto_utils libncursesw)