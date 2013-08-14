#!/bin/sh

(cd rubyssl_src && mkdir -p build && cd build && cmake .. && make)
(mkdir -p libs && cp rubyssl_src/build/*.so libs/)
