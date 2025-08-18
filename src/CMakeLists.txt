add_subdirectory(libs)

# Create the executable from main.c.
add_executable(${PROJECT_NAME} main.c)

# Link the executable with the library.
target_link_libraries(${PROJECT_NAME} PRIVATE dev_disc file_tras)

set_target_properties(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

set_target_properties(dev_disc PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

set_target_properties(file_tras PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)