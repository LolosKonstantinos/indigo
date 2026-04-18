add_subdirectory(gui)
add_subdirectory(tui)
add_subdirectory(cli)
add_subdirectory(indigo_core)

# Create an interface target to hold the include directories.
add_library(crypto_includes INTERFACE crypto_utils.h)

#utilities libraries
add_library(path_includes INTERFACE path.h)
add_library(event_flag_includes INTERFACE event_flags.h)
add_library(queue_includes INTERFACE Queue.h)
add_library(buffer_includes INTERFACE buffer.h)
add_library(mempool_includes INTERFACE mempool.h)
add_library(binary_tree_includes INTERFACE binary_tree.h)
add_library(hash_table_includes INTERFACE dpht.h hash_functions.h hash_table.h lht.h)
add_library(indigo_errors INTERFACE indigo_errors.h)
add_library(indigo_types INTERFACE indigo_types.h)
add_library(config_includes INTERFACE config.h)

# The interface target makes all its consumers aware of the include directory.
target_include_directories(crypto_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(path_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(event_flag_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(queue_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(buffer_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(mempool_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(binary_tree_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(hash_table_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(config_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(indigo_errors INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(indigo_types INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})