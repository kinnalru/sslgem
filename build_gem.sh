#!/bin/sh

mkdir -p build
(cd build && cmake .. && make gem)

mkdir -p image
cp -rf build/image/* image
