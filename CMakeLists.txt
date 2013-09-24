project(libsign C)

cmake_minimum_required(VERSION 2.8)

enable_testing()

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

set(LIBRARY_VERSION_MAJOR 1)
set(LIBRARY_VERSION_MINOR 4)
set(LIBRARY_VERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}")

set(LIBRARY_OUTPUT_PATH ${libsign_BINARY_DIR})
set(LIBRARY_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include/libsign")

# Where to install the .cmake files
if(WIN32 AND NOT CYGWIN)
    set(DEFAULT_CMAKE_DIR cmake)
else()
    set(DEFAULT_CMAKE_DIR "lib/cmake/libsign-${LIBRARY_VERSION}")
endif()
set(CMAKE_INSTALL_PATH ${DEFAULT_CMAKE_DIR} CACHE PATH
    "Installation path for cmake files.")

# parse the Git tag and current revision
include(GetGitRevisionDescription)
git_describe(_revision)

if(NOT WIN32)
	# just until this is implemented in CMake...
	if(${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
		set(CMAKE_COMPILER_IS_CLANG true)
	endif(${CMAKE_C_COMPILER_ID} STREQUAL "Clang")

	# we like warnings.
	if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)
		add_definitions("-Wall -Wextra")
	endif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)
endif(NOT WIN32)

find_package(GMP REQUIRED)

include_directories(${GMP_INCLUDE_DIRS} src)

add_subdirectory(src)
add_subdirectory(tests)

export(TARGETS sign
       FILE "${PROJECT_BINARY_DIR}/signTargets.cmake")
export(PACKAGE libsign)

# create config and version files and install these. Copy FindGMP.cmake as well since windows will store locations configured
# with cmake-gui and search for config files there first.

# for build tree
set(LIBRARY_INCLUDE_DIRS "${PROJECT_BINARY_DIR}/include/libsign")
configure_file(libsign-config.cmake.in "${PROJECT_BINARY_DIR}/libsign-config.cmake" @ONLY)
file(COPY "${CMAKE_MODULE_PATH}/FindGMP.cmake" DESTINATION "${PROJECT_BINARY_DIR}")

# for install tree
set(LIBRARY_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include/libsign")
configure_file(libsign-config.cmake.in "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/libsign-config.cmake" @ONLY)

# for both
configure_file(libsign-config-version.cmake.in "${PROJECT_BINARY_DIR}/libsign-config-version.cmake" @ONLY)

install(FILES
    "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/libsign-config.cmake"
    "${PROJECT_BINARY_DIR}/libsign-config-version.cmake"
    "${CMAKE_MODULE_PATH}/FindGMP.cmake"
    DESTINATION ${CMAKE_INSTALL_PATH})

install(EXPORT signTargets DESTINATION ${CMAKE_INSTALL_PATH} COMPONENT dev)
