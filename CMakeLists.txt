cmake_minimum_required(VERSION 3.4.3)

set(ZLIB_INCLUDE_DIR /usr/include)
set(ZLIB_LIBRARY -lz)
set(CMAKE_BUILD_TYPE Debug)
find_package(ZLIB REQUIRED)
find_package(LLVM REQUIRED CONFIG)
project(play)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

set(LLVM_LINK_COMPONENTS
  x86asmparser 
  x86desc
  x86disassembler
  x86info
  MC
  MCParser
  Support 
)

add_llvm_library(llvmdeps empty.cpp)

add_executable(dis src/dis.cpp)
target_link_libraries(dis llvmdeps)
