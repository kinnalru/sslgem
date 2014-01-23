#!/bin/sh

LOCAL_PREFIX=$1
PREFIX=$LOCAL_PREFIX

export CFLAGS=-fPIC
./config --prefix=${PREFIX} -fPIC --openssldir=${PREFIX}/ssl --install_prefix=${PREFIX}
