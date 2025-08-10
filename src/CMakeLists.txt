add_subdirectory(libs)

# Create the executable from main.c.
add_executable(${PROJECT_NAME} main.c)

# Link the executable with the library.
target_link_libraries(${PROJECT_NAME} PRIVATE dev_disc file_tras)