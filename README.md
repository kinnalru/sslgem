SslGem
========

Gem with libopenssl, wrapper and bindinds bundled.

CMake used to rebuild all subprojects.

How to build:

	mkdir build
	cd build
	cmake ..
	make

Build openssl

	make ssl

Build rubyssl - wrapper

	make ruby

Build gem

	make gem

Build all

	make all


Gem now accessible in build/gem/
