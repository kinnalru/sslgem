require 'rubygems'
require 'base64'
require 'open3'
require 'nokogiri'
require 'fiddle'

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
  
  def initialize
    require 'openssl'
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
    return certs.map do |cert|
      c = OpenSSL::X509::Certificate.new(Base64.decode64(cert.text))
      stdout, stderr, status = Open3.capture3("openssl x509 -noout -text -certopt no_pubkey -certopt no_sigdump -nameopt oneline,-esc_msb", stdin_data: c.to_s, binmode: true)
      
      c.issuer = OpenSSL::X509::Name.parse repack_name(stdout.split("\n").grep(/Issuer/).first, "Issuer")
      c.subject = OpenSSL::X509::Name.parse repack_name(stdout.split("\n").grep(/Subject/).first, "Subject")

      c
    end.uniq{|c| c.serial.to_i}
  end
  
  def repack_name name, type
    return name.sub("#{type}:", "").strip.gsub(" = ", "=").gsub(", ", "/")
  end

end


