@echo off
setlocal EnableDelayedExpansion

REM =========================
REM Configuration
REM =========================

REM Override manually if needed
set NDK_HOME=

set KEYSTONE_REPO=https://github.com/keystone-engine/keystone.git

set ANDROID_PLATFORM=21
set BUILD_TYPE=Release
set JOBS=4

set ARCH_TARGETS=armeabi-v7a arm64-v8a x86 x86_64

set ROOT=%CD%
set SOURCE_PATH=%ROOT%\keystone
set BUILD_PATH=%ROOT%\_keystone_builds_android

set "GENERATOR=Unix Makefiles"


REM =========================
REM Find Android NDK
REM =========================

call :find_ndk

if "%NDK_HOME%"=="" (
    echo ERROR: Android NDK not found
    echo.
    echo Set one of:
    echo   NDK_HOME
    echo   ANDROID_NDK_HOME
    echo   ANDROID_NDK
    echo.
    pause
    exit /b 1
)

echo Using NDK: %NDK_HOME%


REM =========================
REM Prepare source
REM =========================

if exist "%BUILD_PATH%" (
    rmdir /s /q "%BUILD_PATH%"
)

if exist "%SOURCE_PATH%" (
    rmdir /s /q "%SOURCE_PATH%"
)

echo Cloning Keystone...

git clone "%KEYSTONE_REPO%" "%SOURCE_PATH%"

if errorlevel 1 (
    echo ERROR: Failed cloning Keystone
    goto error
)


REM =========================
REM Build
REM =========================

for %%A in (%ARCH_TARGETS%) do (

    set TARGET_BUILD_PATH=%BUILD_PATH%\%%A\build
    set NDK_CMAKE=!NDK_HOME:\=/!

    echo.
    echo ==========================
    echo Building %%A
    echo Path: !TARGET_BUILD_PATH!
    echo ==========================

    mkdir "!TARGET_BUILD_PATH!"

    pushd "!TARGET_BUILD_PATH!"

    cmake ^
    -G "%GENERATOR%" ^
    -S "%SOURCE_PATH%" ^
    -DCMAKE_TOOLCHAIN_FILE="!NDK_CMAKE!/build/cmake/android.toolchain.cmake" ^
    -DANDROID_ABI=%%A ^
    -DANDROID_PLATFORM=android-%ANDROID_PLATFORM% ^
    -DANDROID_STL=c++_static ^
    -DBUILD_LIBS_ONLY=1 ^
    -DBUILD_SHARED_LIBS=OFF ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE%

    if errorlevel 1 (
        echo ERROR: CMake failed for %%A
        popd
        goto error
    )


    cmake --build . --parallel %JOBS%

    if errorlevel 1 (
        echo ERROR: Build failed for %%A
        popd
        goto error
    )

    popd


    copy /y ^
        "!TARGET_BUILD_PATH!\llvm\lib\libkeystone.a" ^
        "%BUILD_PATH%\%%A\libkeystone.a"

    if errorlevel 1 (
        echo ERROR: Copy failed for %%A
        goto error
    )

    echo Built: %BUILD_PATH%\%%A\libkeystone.a
)


goto done


REM =========================
REM Find NDK Function
REM =========================

:find_ndk

for %%V in (ANDROID_NDK_HOME ANDROID_NDK NDK_HOME) do (

    for /f "tokens=2 delims==" %%E in ('set %%V 2^>nul') do (
        if exist "%%E" (
            set NDK_HOME=%%E
            exit /b 0
        )
    )

)


for %%S in (ANDROID_HOME ANDROID_SDK ANDROID_SDK_HOME ANDROID_SDK_ROOT) do (

    for /f "tokens=2 delims==" %%E in ('set %%S 2^>nul') do (

        if exist "%%E\ndk" (

            for /f "delims=" %%N in ('dir /b /ad "%%E\ndk" ^| sort') do (
                set LATEST_NDK=%%N
            )

            if not "!LATEST_NDK!"=="" (
                set NDK_HOME=%%E\ndk\!LATEST_NDK!
                exit /b 0
            )
        )
    )
)

exit /b 1


REM =========================
REM Done
REM =========================

:done

echo.
echo ==========================
echo Keystone Android build complete
echo ==========================

pause
endlocal
exit /b 0


REM =========================
REM Error
REM =========================

:error

echo.
echo ==========================
echo Build failed
echo ==========================

pause
endlocal
exit /b 1
