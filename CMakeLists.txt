project(libsign C)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

set(LIBRARY_OUTPUT_PATH ${libsign_BINARY_DIR})

# parse the Git tag and current revision
include(GetGitRevisionDescription)
git_describe(_revision)

add_subdirectory(src)
add_subdirectory(tests)
