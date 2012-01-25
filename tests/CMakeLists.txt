link_directories(${LIBRARY_OUTPUT_PATH})

# pubkey tests
add_executable(test-parse-binary-pubkey test-parse-pubkey.c)
add_dependencies(test-parse-binary-pubkey sign)
target_link_libraries(test-parse-binary-pubkey sign)
set_target_properties(test-parse-binary-pubkey PROPERTIES
    COMPILE_DEFINITIONS KEYFILE="files/pubkey.key")

add_executable(test-parse-armor-pubkey test-parse-pubkey.c)
add_dependencies(test-parse-armor-pubkey sign)
target_link_libraries(test-parse-armor-pubkey sign)
set_target_properties(test-parse-armor-pubkey PROPERTIES
    COMPILE_DEFINITIONS KEYFILE="files/pubkey.asc")

add_executable(test-parse-binary-pubkey-buffer test-parse-pubkey-buffer.c)
add_dependencies(test-parse-binary-pubkey-buffer sign)
target_link_libraries(test-parse-binary-pubkey-buffer sign)
set_target_properties(test-parse-binary-pubkey-buffer PROPERTIES
    COMPILE_DEFINITIONS KEYFILE="files/pubkey.key")

add_executable(test-parse-armor-pubkey-buffer test-parse-pubkey-buffer.c)
add_dependencies(test-parse-armor-pubkey-buffer sign)
target_link_libraries(test-parse-armor-pubkey-buffer sign)
set_target_properties(test-parse-armor-pubkey-buffer PROPERTIES
    COMPILE_DEFINITIONS KEYFILE="files/pubkey.asc")

# signature tests
add_executable(test-parse-binary-signature test-parse-signature.c)
add_dependencies(test-parse-binary-signature sign)
target_link_libraries(test-parse-binary-signature sign)
set_target_properties(test-parse-binary-signature PROPERTIES
    COMPILE_DEFINITIONS SIGFILE="files/vmImage.sig")

add_executable(test-parse-armor-signature test-parse-signature.c)
add_dependencies(test-parse-armor-signature sign)
target_link_libraries(test-parse-armor-signature sign)
set_target_properties(test-parse-armor-signature PROPERTIES
    COMPILE_DEFINITIONS SIGFILE="files/vmImage.asc")

add_executable(test-parse-binary-signature-buffer test-parse-signature-buffer.c)
add_dependencies(test-parse-binary-signature-buffer sign)
target_link_libraries(test-parse-binary-signature-buffer sign)
set_target_properties(test-parse-binary-signature-buffer PROPERTIES
    COMPILE_DEFINITIONS SIGFILE="files/vmImage.sig")

add_executable(test-parse-armor-signature-buffer test-parse-signature-buffer.c)
add_dependencies(test-parse-armor-signature-buffer sign)
target_link_libraries(test-parse-armor-signature-buffer sign)
set_target_properties(test-parse-armor-signature-buffer PROPERTIES
    COMPILE_DEFINITIONS SIGFILE="files/vmImage.asc")

# verify tests
add_executable(test-verify-binary-key-sig test-verify.c)
add_dependencies(test-verify-binary-key-sig sign)
target_link_libraries(test-verify-binary-key-sig sign)
set_target_properties(test-verify-binary-key-sig PROPERTIES
    COMPILE_DEFINITIONS "KEYFILE=\"files/pubkey.key\";SIGFILE=\"files/vmImage.sig\"")

add_executable(test-verify-armor-key test-verify.c)
add_dependencies(test-verify-armor-key sign)
target_link_libraries(test-verify-armor-key sign)
set_target_properties(test-verify-armor-key PROPERTIES
    COMPILE_DEFINITIONS "KEYFILE=\"files/pubkey.asc\";SIGFILE=\"files/vmImage.sig\"")

add_executable(test-verify-armor-sig test-verify.c)
add_dependencies(test-parse-binary-signature sign)
target_link_libraries(test-verify-armor-sig sign)
set_target_properties(test-verify-armor-sig PROPERTIES
    COMPILE_DEFINITIONS "KEYFILE=\"files/pubkey.key\";SIGFILE=\"files/vmImage.asc\"")

add_executable(test-verify-armor-key-sig test-verify.c)
add_dependencies(test-verify-armor-key-sig sign)
target_link_libraries(test-verify-armor-key-sig sign)
set_target_properties(test-verify-armor-key-sig PROPERTIES
    COMPILE_DEFINITIONS "KEYFILE=\"files/pubkey.asc\";SIGFILE=\"files/vmImage.asc\"")

# copy the test data.
file(COPY "files" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME parse-binary-pubkey COMMAND test-parse-binary-pubkey)
add_test(NAME parse-armor-pubkey COMMAND test-parse-armor-pubkey)
add_test(NAME parse-binary-pubkey-buffer COMMAND test-parse-binary-pubkey-buffer)
add_test(NAME parse-armor-pubkey-buffer COMMAND test-parse-armor-pubkey-buffer)

add_test(NAME parse-binary-signature COMMAND test-parse-binary-signature)
add_test(NAME parse-armor-signature COMMAND test-parse-armor-signature)
add_test(NAME parse-binary-signature-buffer COMMAND test-parse-binary-signature-buffer)
add_test(NAME parse-armor-signature-buffer COMMAND test-parse-armor-signature-buffer)

add_test(NAME verify-binary-key-sig COMMAND test-verify-binary-key-sig)
add_test(NAME verify-armor-key COMMAND test-verify-armor-key)
add_test(NAME verify-armor-sig COMMAND test-verify-armor-sig)
add_test(NAME verify-armor-key-sig COMMAND test-verify-armor-key-sig)
