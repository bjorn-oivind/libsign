# find nettle
find_package(nettle)
if(NOT NETTLE_FOUND)
	message(FATAL_ERROR "Nettle not found.")
endif(NOT NETTLE_FOUND)

include_directories(${NETTLE_INCLUDE_DIR})

if(_revision)
	add_definitions(-DREVISION="${_revision}")
endif(_revision)

# sources
set(LIB_SOURCES
	keystore.h keystore.c
	packet.h packet.c
	sign.h sign.c
	verify.h verify.c)
add_library(sign ${LIB_SOURCES})
target_link_libraries(sign ${NETTLE_LIBRARIES})

# install rules
install(TARGETS sign
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
