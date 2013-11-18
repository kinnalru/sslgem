require 'base64'

class SslGem
    
  
    BUFSIZE=4096
    IMAGEPATH = File.dirname(__FILE__) + "/../ext/ssl/image/"
    ENV['PATH']="#{IMAGEPATH}/bin:#{ENV['PATH']}"

    TESTKEY = File.dirname(__FILE__) + "/keys/seckey.pem"
    TESTCERT = File.dirname(__FILE__) + "/keys/cert.pem"
    
    def initialize
        require "#{IMAGEPATH + "/lib/" + 'sslext.so'}"
        
        class << self
          include SslExt
        end
    end
    
    
end


