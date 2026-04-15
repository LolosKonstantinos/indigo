add_executable(indigo_tests test.c)

target_link_libraries(indigo_tests PRIVATE indigo_core binary_tree)

set_target_properties(indigo_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)