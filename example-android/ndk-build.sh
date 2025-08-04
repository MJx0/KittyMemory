#!/bin/bash

rm -rf build
mkdir -p build
make
mv libs build/libs
mv obj build/obj