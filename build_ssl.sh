#!/bin/sh

(cd openssl_src && ./config && make)
(mkdir -p libs && cp openssl_src/*.a libs/)
