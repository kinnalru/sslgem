#!/bin/sh

mkdir -p build
(cd build && cmake .. && make ruby)

mkdir -p image
cp -rf build/image/* image

