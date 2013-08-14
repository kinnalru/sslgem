require 'fiddle'

class Hola
  def self.hi
    puts "Hello world!"
  end
end

libssl = Fiddle.dlopen(File.dirname(__FILE__) + "/" + 'librubyssl.so')

test = Fiddle::Function.new(
    libssl['c_test'],
    [Fiddle::TYPE_INT],
    Fiddle::TYPE_INT
)

puts test.call(99)
