#!/bin/sh

mkdir -p build
(cd build && cmake .. && make ssl)

mkdir -p image
cp -rf build/image/* image

