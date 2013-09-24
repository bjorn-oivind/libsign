if(_revision)
	add_definitions(-DREVISION="${_revision}")
endif(_revision)

include(TestBigEndian)
test_big_endian(BIG_ENDIAN)
if(BIG_ENDIAN)
        message(FATAL_ERROR "Big endian currently not supported.")
endif(BIG_ENDIAN)

# sources
set(LIB_SOURCES
        armor.h armor.c
        cdecode.c cencode.c
        key.h
	keystore.h keystore.c
        mpi.h mpi.c
	packet.h packet.c
        pgp.h pgp.c
        public_key.h public_key.c
        rsa.h rsa.c
        secret_key.h secret_key.c
        signature.h signature.c
	sign.h sign.c
        sha1.h sha1.c
	verify.h verify.c)
# headers
set(LIB_HEADERS
        armor.h
        public_key.h
        secret_key.h
        sign.h
        signature.h
        verify.h
        pgp.h)

add_library(sign STATIC ${LIB_SOURCES})
target_link_libraries(sign ${GMP_LIBRARIES})

# compile with -fPIC if we need to
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_COMPILER_IS_GNUCC AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set_target_properties(sign PROPERTIES COMPILE_FLAGS "-fPIC")
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_COMPILER_IS_GNUCC AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")

# copy headers to build dir in case we want to compile upstream from there.
file(COPY ${LIB_HEADERS} DESTINATION "${PROJECT_BINARY_DIR}/include/libsign")

set_target_properties(sign PROPERTIES
                      PUBLIC_HEADER "${LIB_HEADERS}"
                      SOVERSION ${LIBRARY_VERSION_MAJOR}
                      VERSION ${LIBRARY_VERSION_MINOR})

# install rules
install(TARGETS sign
        EXPORT signTargets
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION "${LIBRARY_INCLUDE_DIRS}" COMPONENT dev)
