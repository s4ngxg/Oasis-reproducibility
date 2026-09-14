cmake_minimum_required(VERSION 3.22)
project(SCHNORR C)

set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-macro-redefined")
if(APPLE)
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3")
else()
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3 -Wno-clobbered")
endif()

set(LOCAL_DEPS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/.local-deps)
set(LOCAL_INCLUDE_DIRS
  ${LOCAL_DEPS_DIR}/usr/local/include
  ${LOCAL_DEPS_DIR}/usr/include
  ${LOCAL_DEPS_DIR}/usr/include/x86_64-linux-gnu
)
set(LOCAL_LIBRARY_DIRS
  ${LOCAL_DEPS_DIR}/usr/local/lib
  ${LOCAL_DEPS_DIR}/usr/lib/x86_64-linux-gnu
)

# add extra include directories
set(INCLUDE
  /usr/local/include
  /usr/include
  ${LOCAL_INCLUDE_DIRS}
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/include
)
include_directories(${INCLUDE})

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(CMAKE_BUILD_RPATH "${LOCAL_LIBRARY_DIRS}")
set(CMAKE_INSTALL_RPATH "${LOCAL_LIBRARY_DIRS}")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

set(SIMUL "$ENV{SIMUL}" CACHE STRING "Path to call a simulator of the target platform.")
set(SIMAR "$ENV{SIMAR}" CACHE STRING "Arguments to call a simulator of the target platform.")
string(REPLACE " " ";" SIMAR "${SIMAR}")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/src)
file(GLOB includes "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
