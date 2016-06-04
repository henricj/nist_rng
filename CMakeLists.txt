cmake_minimum_required (VERSION 2.8)
project (nist_rng)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include(cmake/PlatformSettings.cmake)

include_directories(include)

add_subdirectory(include)
add_subdirectory(lib)
if (NOT IOS)
    add_subdirectory(kat)
    add_subdirectory(programs)
endif (NOT IOS)

