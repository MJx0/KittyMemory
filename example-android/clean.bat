@ECHO OFF
SETLOCAL

SET CMAKE_BUILD_DIR=cmake_build
SET NDK_BUILD_DIR=ndk_build

ECHO ===============================
ECHO Cleaning build artifacts
ECHO ===============================

IF EXIST "%CMAKE_BUILD_DIR%" (
    ECHO Removing %CMAKE_BUILD_DIR% ...
    rmdir /S /Q "%CMAKE_BUILD_DIR%"
)

IF EXIST "%NDK_BUILD_DIR%" (
    ECHO Removing %NDK_BUILD_DIR% ...
    rmdir /S /Q "%NDK_BUILD_DIR%"
)

IF EXIST "compile_commands.json" (
    ECHO Removing compile_commands.json ...
    del /F /Q "compile_commands.json"
)

ECHO Done.
ENDLOCAL

PAUSE
