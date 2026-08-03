cmake_minimum_required(VERSION 3.21)

project(ExampleProject LANGUAGES C CXX OBJCXX)

# -----------------------------
# Options
# -----------------------------
option(NO_KEYSTONE "Disable Keystone support" OFF)

# -----------------------------
# C++ standard
# -----------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================================
# KittyMemory
# ============================================================================
set(KITTYMEMORY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../KittyMemory")
set(KEYSTONE_LIB "${KITTYMEMORY_PATH}/Deps/Keystone/libs-ios/${CMAKE_OSX_ARCHITECTURES}/libkeystone.a")

# -----------------------------
# Project sources
# -----------------------------
file(GLOB KITTYMEMORY_SRC
    "${KITTYMEMORY_PATH}/*.cpp"
)

# -----------------------------
# Shared Library
# -----------------------------
add_library(ExampleProject SHARED
    Tweak.mm
    ${KITTYMEMORY_SRC}
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
        -fobjc-arc
        -Wall
        -Wextra
        -Werror
        -fexceptions
        -Wno-unused-command-line-argument
)

# -----------------------------
# Platform-specific libraries
# -----------------------------
target_link_libraries(ExampleProject PRIVATE "-framework Foundation -framework UIKit" $<$<NOT:$<BOOL:${KT_DISABLE_KEYSTONE}>>:${KEYSTONE_LIB}>)
set_target_properties(ExampleProject PROPERTIES
        XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "14.0"
    )

# ============================================================================
# Architectures / Deployment Target
# ============================================================================
set(CMAKE_OSX_ARCHITECTURES "arm64;arm64e" CACHE STRING "" FORCE)
set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "" FORCE)