#!/bin/sh

LOCAL_PREFIX=$1
PREFIX=$LOCAL_PREFIX

export CFLAGS=-fPIC
./config --prefix=${PREFIX} -fPIC -shared --openssldir=${PREFIX}/ssl/ 
