cmake_minimum_required(VERSION 3.4.3)

project(s2)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options("-fno-rtti")
add_compile_options("-Wno-format-security")
add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
add_link_options(-fsanitize=address -fno-omit-frame-pointer)

set(ZLIB_INCLUDE_DIR /usr/include)
set(ZLIB_LIBRARY -lz)
set(CMAKE_BUILD_TYPE Debug)
find_package(ZLIB REQUIRED)
find_package(LLVM REQUIRED CONFIG)

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

add_executable(
  s2
  src/translater.cpp
  src/runtime.cpp
  src/elf_file.cpp
  src/utils.cpp
  src/main.cpp
)

add_llvm_library(llvmdeps empty.cpp)
target_link_libraries(s2 llvmdeps)
