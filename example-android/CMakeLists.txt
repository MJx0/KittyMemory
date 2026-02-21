cmake_minimum_required(VERSION 3.16)

project(ExampleProject
    VERSION 1.0
    LANGUAGES CXX
)

# -----------------------------
# Options
# -----------------------------
option(KT_DISABLE_KEYSTONE "Disable keystone support" OFF)

# -----------------------------
# C++ standard
# -----------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -----------------------------
# KittyMemory library
# -----------------------------
set(KITTYMEMORY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../KittyMemory")
file(GLOB KITTYMEMORY_SRC "${KITTYMEMORY_PATH}/*.cpp")
set(KEYSTONE_LIB ${KITTYMEMORY_PATH}/Deps/Keystone/libs-android/${CMAKE_ANDROID_ARCH_ABI}/libkeystone.a)

# -----------------------------
# Project sources
# -----------------------------
file(GLOB PROJ_SRC
    "example.cpp"
)

# -----------------------------
# Shared Library
# -----------------------------
add_library(ExampleProject SHARED ${PROJ_SRC} ${KITTYMEMORY_SRC})


# -----------------------------
# Includes
# -----------------------------
target_include_directories(ExampleProject
    PRIVATE
        ${KITTYMEMORY_PATH}
)

# -----------------------------
# Compile definitions
# -----------------------------
target_compile_definitions(ExampleProject
    PRIVATE
        $<$<CONFIG:Debug>:DEBUG>
        $<$<CONFIG:Release>:NDEBUG>
        $<$<BOOL:${KT_DISABLE_KEYSTONE}>:kNO_KEYSTONE>
)

# -----------------------------
# Compile options
# -----------------------------
target_compile_options(ExampleProject
    PRIVATE
        $<$<CONFIG:Debug>:-O0 -g>
        $<$<CONFIG:Release>:-O2>
        -Wall
        -Wextra
        -Werror
        -fexceptions
        -Wno-unused-command-line-argument
)

# -----------------------------
# Platform-specific libraries
# -----------------------------
if(ANDROID)
    target_link_libraries(ExampleProject PRIVATE log $<$<NOT:$<BOOL:${KT_DISABLE_KEYSTONE}>>:${KEYSTONE_LIB}>)
endif()