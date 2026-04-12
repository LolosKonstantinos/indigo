add_executable(indigo_tests test.c)

target_link_libraries(indigo_tests PRIVATE indigo_core)