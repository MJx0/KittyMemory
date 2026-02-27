@ECHO OFF
SETLOCAL ENABLEDELAYEDEXPANSION

:: ===============================
:: Config
:: ===============================
SET "NDK=%NDK_HOME%"
SET "BUILD_TYPE=Release"
SET "ANDROID_API=21"
SET "ABIs=arm64-v8a armeabi-v7a x86 x86_64"

SET "CMAKE=cmake"
SET "GENERATOR=Ninja"

SET "CMAKE_BUILD_DIR=cmake_build"
SET "NDK_BUILD_DIR=ndk_build"

:: ===============================
:: Detect cores
:: ===============================
SET "JOBS=4"
IF DEFINED NUMBER_OF_PROCESSORS (
    SET /A JOBS=%NUMBER_OF_PROCESSORS% / 2
)

:: ===============================
:: Validate NDK
:: ===============================
IF "%NDK%"=="" (
    ECHO ERROR: env variable NDK_HOME not set.
    PAUSE
    EXIT /B 1
)

:: ===============================
:: Menu
:: ===============================
ECHO.
ECHO Select build system:
ECHO   [1] CMake
ECHO   [2] ndk-build
ECHO.

SET /P CHOICE=Enter choice (1 or 2):

IF "%CHOICE%"=="1" GOTO BUILD_CMAKE
IF "%CHOICE%"=="2" GOTO BUILD_NDK

ECHO Invalid choice.
PAUSE
EXIT /B 1

:: ===============================
:: CMake build
:: ===============================
:BUILD_CMAKE
FOR %%A IN (%ABIs%) DO (
    ECHO ==================================
    ECHO CMake build - ABI "%%A"
    ECHO ==================================

    %CMAKE% -S . -B "%CMAKE_BUILD_DIR%\%%A" ^
        -G "%GENERATOR%" ^
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ^
        -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
        -DCMAKE_TOOLCHAIN_FILE=%NDK%\build\cmake\android.toolchain.cmake ^
        -DANDROID_ABI=%%A ^
        -DANDROID_PLATFORM=android-%ANDROID_API% ^
        -DANDROID_STL=c++_static

    %CMAKE% --build "%CMAKE_BUILD_DIR%\%%A" -- -j%JOBS%
)
PAUSE
GOTO :EOF

:: ===============================
:: ndk-build
:: ===============================
:BUILD_NDK
CALL "%NDK%\ndk-build.cmd" -j%JOBS% ^
    NDK_PROJECT_PATH=. ^
    APP_BUILD_SCRIPT=Android.mk ^
    NDK_APPLICATION_MK=Application.mk ^
    NDK_OUT="%NDK_BUILD_DIR%\obj" ^
    NDK_LIBS_OUT="%NDK_BUILD_DIR%\libs"
PAUSE
GOTO :EOF
