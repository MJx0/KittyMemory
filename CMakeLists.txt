cmake_minimum_required(VERSION 3.21)

project(KittyMemory)

if(CMAKE_SYSTEM_NAME STREQUAL "Android" OR ANDROID)
    message(STATUS "Configuring Android project")
    add_subdirectory(example-android)
elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    message(STATUS "Configuring iOS project")
    add_subdirectory(example-ios)
else()
    message(FATAL_ERROR "Unsupported platform: '${CMAKE_SYSTEM_NAME}'. Set -DCMAKE_SYSTEM_NAME=Android or iOS.")
endif()
