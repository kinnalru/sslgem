require 'base64'
require 'open3'

class SslGem
    
  
    BUFSIZE=4096
    IMAGEPATH = File.dirname(__FILE__) + "/image/"
    ENV['PATH']="#{IMAGEPATH}/bin:#{ENV['PATH']}"

	TESTKEY = File.dirname(__FILE__) + "/keys/seckey.pem"
	TESTCERT = File.dirname(__FILE__) + "/keys/cert.pem"
    
    class Error < RuntimeError
        def initialize(message)
            super(message)
        end
    end
    
	def dgst key, data
        stdout, stderr, status = Open3.capture3("openssl dgst -engine gost -sign #{key}", stdin_data: data, binmode: true)

		if status.success?
            return (Base64.encode64 stdout).strip
		else
			raise Error.new("dgst failed: #{stderr}")
		end
	end


	def verify_file signature, file
        stdout, stderr, status = Open3.capture3("openssl smime -verify -engine gost -noverify -inform DER -in #{signature} -content #{file}", binmode: true)

		if status.success?
            return /successful/ =~ stdout
		else
			raise Error.new("verify_file failed: #{stderr}")
		end
	end

	def sign_file key, cert, file
        stdout, stderr, status = Open3.capture3("openssl smime -sign -engine gost -gost89  -inkey #{key} -signer #{cert} -in #{file} -outform DER -binary", binmode: true)

		if status.success?
	        return stdout.strip
		else
			raise Error.new("sign_file failed: #{stderr}")
		end
	end

    
end


