cmake_minimum_required(VERSION 3.5)

project(KittyMemoryExample)

set(KITTYMEMORY_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../KittyMemory)
file(GLOB KITTYMEMORY_SRC ${KITTYMEMORY_PATH}/*.cpp)
set(KEYSTONE_LIB ${KITTYMEMORY_PATH}/Deps/Keystone/libs-android/${CMAKE_ANDROID_ARCH_ABI}/libkeystone.a)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument -O0 -g -std=c++20 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument -O2 -s -std=c++20 -DNDEBUG")

add_library(KittyMemoryExample SHARED example.cpp ${KITTYMEMORY_SRC})

target_include_directories(KittyMemoryExample PUBLIC ${KITTYMEMORY_PATH})
target_link_libraries(KittyMemoryExample -llog ${KEYSTONE_LIB})