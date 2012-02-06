# Find nettle
#
# This module defines
#  NETTLE_FOUND - whether the nettle library and its dependecies were found
#  NETTLE_LIBRARIES - the nettle library and its dependencies
#  NETTLE_INCLUDE_DIR - the include paths of the nettle library and its dependencies
#  NETTLE_LIBRARY_DIR - the paths of the nettle library and its dependencies
#  NETTLE_LIBRARY_DLL - the absolute path to the library on windows (only set on WIN32).
#

if (NETTLE_INCLUDE_DIR AND NETTLE_LIBRARIES AND NETTLE_LIBRARY_DIR)

  # Already in cache
  set (NETTLE_FOUND TRUE)

else (NETTLE_INCLUDE_DIR AND NETTLE_LIBRARIES AND NETTLE_LIBRARY_DIR)

  if (NOT WIN32)
    set(NETTLE_LIBRARY_DIR "/usr/lib")
    set(NETTLE_INCLUDE_DIR "/usr/include/nettle")
  else(NOT WIN32)
    file(TO_CMAKE_PATH "$ENV{PROGRAMFILES}/nettle/lib" NETTLE_LIBRARY_DIR)
    file(TO_CMAKE_PATH "$ENV{PROGRAMFILES}/nettle/include" NETTLE_INCLUDE_DIR)
	file(TO_CMAKE_PATH "$ENV{PROGRAMFILES}/mpir/lib" MPIR_LIBRARY_DIR)
	file(TO_CMAKE_PATH "$ENV{PROGRAMFILES}/mpir/include" MPIR_INCLUDE_DIR)	
  endif (NOT WIN32)

  find_library (NETTLE_LIBRARIES
    NAMES
    nettle
    PATHS
    ${NETTLE_LIBRARY_DIR}
    ${LIB_INSTALL_DIR}
  )

  find_path (NETTLE_INCLUDE_DIR
    NAMES
    nettle-types.h
    PATHS
    ${NETTLE_INCLUDE_DIR}
    ${INCLUDE_INSTALL_DIR}
  )

  if(WIN32)
    if(MINGW)
	  file(TO_CMAKE_PATH "$ENV{PROGRAMFILES}/nettle/bin/libnettle.dll" NETTLE_LIBRARY_DLL)
    elseif(MSVC)
	  file(TO_CMAKE_PATH "$ENV{PROGRAMFILES}/nettle/bin/nettle.dll" NETTLE_LIBRARY_DLL)
    endif(MINGW)
	
	# We need to find the mpir dependency as well
    find_library (MPIR_LIBRARY
      NAMES
      mpir
      PATHS
      ${MPIR_LIBRARY_DIR}
      ${LIB_INSTALL_DIR}
    )
	
	if(NOT MPIR_LIBRARY)
	    Message(FATAL_ERROR "Nettle dependency mpir not found.")
	endif(NOT MPIR_LIBRARY)
	
	list(APPEND NETTLE_LIBRARIES ${MPIR_LIBRARY})
	list(APPEND NETTLE_INCLUDE_DIR ${MPIR_INCLUDE_DIR})
	
    set(NETTLE_FOUND 1)
  else(WIN32)
	# We require hogweed as well as gmp on Linux
	find_library (GMP_LIBRARY
		NAMES
		gmp
		PATHS
		${NETTLE_LIBRARY_DIR}
		${LIB_INSTALL_DIR}
	)
	
	if(NOT GMP_LIBRARY)
		Message(FATAL_ERROR "Nettle dependency gmp not found.")
	endif(NOT GMP_LIBRARY)
	
	find_library (HOGWEED_LIBRARY
		NAMES
		hogweed
		PATHS
		${NETTLE_LIBRARY_DIR}
		${LIB_INSTALL_DIR}
	)
	
	if(NOT HOGWEED_LIBRARY)
		Message(FATAL_ERROR "Nettle dependency hogweed not found.")
	endif(NOT HOGWEED_LIBRARY)
	
	list(APPEND NETTLE_LIBRARIES ${GMP_LIBRARY})
	list(APPEND NETTLE_LIBRARIES ${HOGWEED_LIBRARY})
	set(NETTLE_FOUND 1)
  endif(WIN32)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Nettle DEFAULT_MSG NETTLE_LIBRARIES NETTLE_INCLUDE_DIR NETTLE_LIBRARY_DIR)

endif (NETTLE_INCLUDE_DIR AND NETTLE_LIBRARIES AND NETTLE_LIBRARY_DIR)
