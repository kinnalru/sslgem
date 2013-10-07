require 'fiddle'


class SslGem
    
    BUFSIZE=4096
    IMAGEPATH = File.dirname(__FILE__) + "/image/"
    ENV['PATH']="#{IMAGEPATH}/bin:#{ENV['PATH']}"
    
    class Error < RuntimeError
        def initialize(message)
            super(message)
        end
    end
    
    def initialize
        @libssl = Fiddle.dlopen(IMAGEPATH+ "/lib/" + 'librubyssl.so')
        
        attach_function(:dgst,
            [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
            Fiddle::TYPE_INT
        )
        
        attach_function(:verify_file,
            [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
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
                
                status = instance_eval("@#{@@tmpname}").call(*args, result_ptr, BUFSIZE, error_ptr, BUFSIZE)
                if (status == 0)
                    return result_ptr.to_s
                else
                    raise SslGem::Error.new(error_ptr.to_s)
                end
            end
        end
    end
    
    
end


