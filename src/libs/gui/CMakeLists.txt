add_library(gui SHARED gui.cpp)


find_package(Qt6 COMPONENTS Widgets REQUIRED)
target_link_libraries(gui PRIVATE gui_includes Qt6::Widgets)