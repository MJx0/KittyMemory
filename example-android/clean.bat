@ECHO off
make clean
if exist "libs" RMDIR "libs" /S /Q
if exist "obj" RMDIR "obj" /S /Q
pause