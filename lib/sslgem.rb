require 'rubygems'
require 'base64'
require 'open3'
require 'nokogiri'
require 'fiddle'

require 'openssl'

module Ssl

  class SslGem

    IMAGEPATH = File.dirname(__FILE__) + "/../ext/ssl/image/"
    ENV['PATH']="#{IMAGEPATH}/bin:#{ENV['PATH']}"
    SSLLIB = Fiddle::Handle.new(IMAGEPATH + "/lib/libopenssl.so", Fiddle::RTLD_LAZY | Fiddle::RTLD_GLOBAL)

    TESTKEY = File.dirname(__FILE__) + "/test/seckey.pem"
    TESTCERT = File.dirname(__FILE__) + "/test/cert.pem"
    TESTRESPONSE = File.dirname(__FILE__) + "/test/response"

    class Error < RuntimeError
      def initialize(message)
        super(message)
      end
    end
    
    def info
      return "SslGem info:\n
        using openssl: #{`which openssl`}\n
        version: #{`openssl version -a`}
        engines: #{`openssl engine -t`}
      "
    end

    def dgst data
      stdout, stderr, status = Open3.capture3('openssl dgst -engine gost -md_gost94 -binary', stdin_data: data, binmode: true)

      if status.success?
        return (Base64.encode64 stdout).strip
      else
        raise Error.new("dgst failed: #{stderr}")
      end
    end
      
    def sign key, data
      stdout, stderr, status = Open3.capture3("openssl dgst -engine gost -sign #{key}", stdin_data: data, binmode: true)

      if status.success?
        return (Base64.encode64 stdout).strip
      else
        raise Error.new("sign failed: #{stderr}")
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
    
    def extract_certs rawxml
      xml = Nokogiri.XML(rawxml)
      xml.remove_namespaces!
      certs = []
      certs += xml.search('X509Certificate')
      certs +=  xml.search('BinarySecurityToken')
      return certs.map() do |cert|
        begin
          Ssl::Certificate.new(Base64.decode64(cert.text))
        rescue
          nil
        end
      end.uniq{|c| c.serial.to_i}.select{|c| c}
    end
    
  end

  class Certificate < OpenSSL::X509::Certificate
    def initialize args = nil
      
      if args.nil?
        return
      else
        super(args)
      end
      
      begin
        stdout, stderr, status = Open3.capture3('openssl x509 -noout -text -certopt no_pubkey -certopt no_sigdump -nameopt oneline,-esc_msb', stdin_data: self.to_s, binmode: true)
        stdout = stdout.split("\n")
      rescue => e
        puts "Exception1: #{e}"
        return
      end
      
      begin
        self.issuer = OpenSSL::X509::Name.parse repack_name(stdout.grep(/Issuer/).first, 'Issuer')
      rescue => e
        puts "Exception2: #{e}"
      end
      
      begin
        self.subject = OpenSSL::X509::Name.parse repack_name(stdout.grep(/Subject/).first, 'Subject')
      rescue => e
        puts "Exception3: #{e}"
      end
      
      begin
        not_after = Time.parse(self.not_after.to_s).utc
        not_before = Time.parse(self.not_before.to_s).utc
      rescue => e
        puts "Exception4: #{e}"
      end
      
    rescue => e
      puts "Exception5: #{e}"
      raise e
    end
    
    def subjectx
        self.subject.to_a.inject({}) do |ret, v| ret[v[0]] = v[1].force_encoding('utf-8'); ret; end 
  end
    
    def issuerx
      self.issuer.to_a.inject({}) do |ret, v| ret[v[0]] = v[1].force_encoding('utf-8'); ret; end
    end

    def extensionsx
      return self.extensions.inject({}) do |ret, ext|
        ret[ext.oid] = ext.to_h
        
        priv = ret['privateKeyUsagePeriod']
        if priv
          not_before, not_after = priv['value'].split(',')
          
          not_before = not_before.sub('Not Before:', '').strip
          not_after = not_after.sub('Not After:', '').strip
          
          priv['Not Before'] = Time.parse(not_before).utc
          priv['Not After'] = Time.parse(not_after).utc
          ret['privateKeyUsagePeriod'] = priv
        end
        
        ret
      end
    end
    
    def expired?
      now = Time.new
      return ((now < not_before) || (not_after < now)) || private_expired?
    end
      
    def private_expired?
      if (key = extensionsx['privateKeyUsagePeriod'])
        now = Time.new
        return (now < key['Not Before']) || (key['Not After'] < now)
      end
      return false
    end
    
    def to_expired
      return not_after - Time.now
    end
    
    def repack_name name, type
      return name.sub("#{type}:", '').strip.gsub(" = ", "=").gsub(", ", "/")
    end
    
  end

end



