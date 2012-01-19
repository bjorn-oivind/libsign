link_directories(${LIBRARY_OUTPUT_PATH})

add_executable(test-keystore test-keystore.c)
add_dependencies(test-keystore sign)
target_link_libraries(test-keystore sign)
add_executable(test-verify test-verify.c)
add_dependencies(test-verify sign)
target_link_libraries(test-verify sign)
add_executable(test-verify-with-armor test-verify-with-armor.c)
add_dependencies(test-verify-with-armor sign)
target_link_libraries(test-verify-with-armor sign)
add_executable(test-sign test-sign.c)
add_dependencies(test-sign sign)
target_link_libraries(test-sign sign)

# copy the test data.
file(COPY "files" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME keystore COMMAND test-keystore)
add_test(NAME verify COMMAND test-verify)
add_test(NAME verify-with-armor COMMAND test-verify-with-armor)
add_test(NAME sign COMMAND test-sign)
