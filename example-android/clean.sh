#!/usr/bin/env bash
set -e

CMAKE_BUILD_DIR="cmake_build"
NDK_BUILD_DIR="ndk_build"

echo "==============================="
echo "Cleaning build artifacts"
echo "==============================="

if [[ -d "$CMAKE_BUILD_DIR" ]]; then
  echo "Removing $CMAKE_BUILD_DIR ..."
  rm -rf "$CMAKE_BUILD_DIR"
fi

if [[ -d "$NDK_BUILD_DIR" ]]; then
  echo "Removing $NDK_BUILD_DIR ..."
  rm -rf "$NDK_BUILD_DIR"
fi

if [[ -f "compile_commands.json" ]]; then
  echo "Removing compile_commands.json ..."
  rm -f "compile_commands.json"
fi

echo "Done."
