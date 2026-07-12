add_library(tui SHARED tui.c)

target_link_libraries(tui PUBLIC tui_includes)

target_link_libraries(tui PRIVATE crypto_utils ncursesw PkgConfig::GLIB tp_logger PkgConfig::SODIUM binary_tree config queue)
if(WIN32)
    target_link_libraries(tui PRIVATE ws2_32)
endif ()