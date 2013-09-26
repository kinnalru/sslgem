require 'fiddle'

class SslGem
  def self.hi
    puts "Hello world!"
  end
end

libssl = Fiddle.dlopen(File.dirname(__FILE__) + "/" + 'librubyssl.so')

# test = Fiddle::Function.new(
#     libssl['c_test'],
#     [Fiddle::TYPE_INT],
#     Fiddle::TYPE_INT
# )

dgst = Fiddle::Function.new(
    libssl['dgst'],
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
    Fiddle::TYPE_VOIDP
)

puts test.call(99)

puts dgst.call("/home/jerry/devel/examples/keys/seckey.pem", "hello")


