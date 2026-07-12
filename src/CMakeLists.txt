add_subdirectory(libs)

# Create the executable from main.c.
add_executable(${PROJECT_NAME}_tui main_tui.c)

add_executable(${PROJECT_NAME}_gui main_gui.c)

# Link the executable with the library.
target_include_directories(${PROJECT_NAME}_tui PRIVATE ${SODIUM_STATIC_LIBRARY_DIRS})
target_link_libraries(${PROJECT_NAME}_tui PRIVATE indigo_core
                                                  crypto_utils
                                                  queue
                                                  binary_tree
                                                  tui
                                                  ncursesw
                                                  ${SODIUM_STATIC_LIBRARIES}
                                                  logger
                                                  tp_logger
                                                  config
)
if(WIN32)
    target_link_libraries(${PROJECT_NAME}_tui PRIVATE ws2_32 IPHLPAPI)
endif ()