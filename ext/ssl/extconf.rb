require 'mkmf'

unless find_executable('cmake')
	puts "cmake not found"
	exit 1
end

puts "Using prepackaged Makefile..."

