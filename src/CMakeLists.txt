add_subdirectory(libs)

# Create the executable from main.c.
add_executable(${PROJECT_NAME} main.c)

# Link the executable with the library.
target_link_libraries(${PROJECT_NAME} PRIVATE dev_disc)

# Add the library target compiled from the source files in the 'lib' subdirectory.
add_library(dev_disc SHARED
        libs/device_discovery.c
        libs/Queue.c
        libs/dynamic_array.c
)

# Link the library target with the interface target so that it knows where to find headers.
target_link_libraries(dev_disc PUBLIC dev_disc_includes ws2_32 IPHLPAPI)