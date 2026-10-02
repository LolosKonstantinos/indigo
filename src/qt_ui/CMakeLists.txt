set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

add_library(qt_ui STATIC qt_ui.cpp qt_ui.h qt_ui_global.h
    mainwindow.h mainwindow.cpp mainwindow.ui
    login_dialog.h login_dialog.cpp login_dialog.ui
)
add_library(ui_interface SHARED ui_interface.cpp ui_interface.h)


target_link_libraries(qt_ui PRIVATE Qt${QT_VERSION_MAJOR}::Core)
target_link_libraries(ui_interface PUBLIC qt_ui)