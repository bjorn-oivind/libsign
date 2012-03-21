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
        public_key.h public_key.c
        secret_key.h secret_key.c
        signature.h signature.c
	sign.h sign.c
	verify.h verify.c)
add_library(sign STATIC ${LIB_SOURCES})
target_link_libraries(sign ${Nettle_LIBRARIES})

# compile with -fPIC if we need to
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_COMPILER_IS_GNUCC AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set_target_properties(sign PROPERTIES COMPILE_FLAGS "-fPIC")
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_COMPILER_IS_GNUCC AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")

# install rules
install(TARGETS sign
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)

# include files
install(FILES armor.h
                public_key.h
                secret_key.h
                sign.h
                signature.h
                verify.h
        DESTINATION include/libsign)
