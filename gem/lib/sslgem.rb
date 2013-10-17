require 'fiddle'
require 'base64'

class SslGem
    
  
    BUFSIZE=4096
    IMAGEPATH = File.dirname(__FILE__) + "/../ext/ssl/image/"
    ENV['PATH']="#{IMAGEPATH}/bin:#{ENV['PATH']}"

	TESTKEY = File.dirname(__FILE__) + "/keys/seckey.pem"
	TESTCERT = File.dirname(__FILE__) + "/keys/cert.pem"
    
    class Error < RuntimeError
        def initialize(message)
            super(message)
        end
    end
    
    def initialize
        @libssl = Fiddle.dlopen(IMAGEPATH+ "/lib/" + 'libsslext.so')
        
        attach_function(:dgst,
            [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
            Fiddle::TYPE_INT
        ) do |data|
          Base64.encode64(data)
        end
        
        attach_function(:verify_file,
            [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
            Fiddle::TYPE_INT
        )
        
        attach_function(:sign_file,
            [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
            Fiddle::TYPE_INT
        )
        
    end
    
    
private

    def attach_function name, signature, result
        #defining variable to wrap c-function
        instance_eval("
            @#{name} = Fiddle::Function.new( 
                @libssl['#{name}'],
                #{signature},
                #{result}
            )
        ")
        
        #declaring function to handle c-function call
        @@tmpname = name
        class << self
            define_method(@@tmpname) do |*args|
                result_ptr = Fiddle::Pointer::malloc(BUFSIZE)
                error_ptr = Fiddle::Pointer::malloc(BUFSIZE)
                size_ptr = Fiddle::Pointer::malloc(BUFSIZE)
                
                result_size = size_ptr.to_s.to_i
                status = instance_eval("@#{__method__}").call(*args, result_ptr, size_ptr, error_ptr, BUFSIZE)
                result_size = size_ptr.to_s.to_i
                if (status == 0)
                  if block_given?
                    return yield result_ptr.to_s(result_size)
                  else
                    return result_ptr.to_s(result_size)
                  end
                else
                    raise SslGem::Error.new(error_ptr.to_s)
                end
            end
        end
    end
    
    
end


