project(libsign C)

cmake_minimum_required(VERSION 2.8)

enable_testing()

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

set(LIBRARY_OUTPUT_PATH ${libsign_BINARY_DIR})

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

# find nettle
find_package(nettle)
if(NOT NETTLE_FOUND)
	message(FATAL_ERROR "Nettle not found.")
endif(NOT NETTLE_FOUND)

include_directories(${NETTLE_INCLUDE_DIR} src)

add_subdirectory(src)
add_subdirectory(tests)
