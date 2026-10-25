add_library(ui SHARED ui.c)
add_library(verify_user_tui STATIC verify_user_tui.c)
add_library(verify_user_gui STATIC verify_user_gui.cpp)


target_link_libraries(ui PUBLIC ui_includes)
target_link_libraries(verify_user_tui PUBLIC ui_includes)

target_link_libraries(ui PRIVATE crypto_utils ncursesw PkgConfig::GLIB tp_logger PkgConfig::SODIUM binary_tree config queue)
if(WIN32)
    target_link_libraries(ui PRIVATE ws2_32)
endif ()

target_link_libraries(verify_user_tui PRIVATE crypto_utils ncursesw PkgConfig::GLIB tp_logger)