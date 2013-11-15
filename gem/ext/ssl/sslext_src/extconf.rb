# Loads mkmf which is used to make makefiles for Ruby extensions
require 'mkmf'

@extlibdir=ENV['IMAGE_DIR'] + '/lib'

find_library('openssl','main', @extlibdir)
find_library('ssl',    'main', @extlibdir)
find_library('crypto', 'main', @extlibdir)

have_library("stdc++")

create_makefile('sslext')
