#!/bin/sh

(cd gem &&  cp ../libs/librubyssl.so lib && gem build sslgem.gemspec && cp *.gem ../libs && mv *.gem ../ && cp lib/*.rb ../libs)
