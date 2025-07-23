# Create an interface target to hold the include directories.
add_library(dev_disc_includes INTERFACE
        Queue.h
        device_discovery.h
        dynamic_array.h)

# The interface target makes all its consumers aware of the include directory.
target_include_directories(dev_disc_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})