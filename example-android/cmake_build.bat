@ECHO OFF

:: Path to ndk
SET "NDK=%NDK_HOME%"

:: Path to cmake
SET "CMAKE=cmake"

:: Path to cmake
SET "MAKE=make"

SET BUILD_PATH=cmake_builds

:: Targets
SET "ABIs=arm64-v8a armeabi-v7a x86 x86_64"

for %%x in (%ABIs%) do (
    ECHO ==========================
    ECHO = Building %%x
    ECHO ==========================

    CMAKE -S. -B%BUILD_PATH%/%%x -G "Unix Makefiles" ^
    -DCMAKE_EXPORT_COMPILE_COMMANDS=TRUE ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_TOOLCHAIN_FILE=%NDK%/build/cmake/android.toolchain.cmake ^
    -DCMAKE_C_COMPILER=%NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe ^
    -DCMAKE_CXX_COMPILER=%NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe ^
    -DANDROID_NDK=%NDK% ^
    -DANDROID_ABI=%%x ^
    -DANDROID_NATIVE_API_LEVEL=21

    MAKE -C%BUILD_PATH%/%%x -j16
)

PAUSE
