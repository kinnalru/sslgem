require 'rubygems'
require 'base64'
require 'open3'
require 'nokogiri'
require 'smev'
require 'fiddle'
require 'ostruct'

require 'openssl'

module Ssl

  class SslGem

    IMAGEPATH = File.dirname(__FILE__) + "/../ext/ssl/image/"
    ENV['PATH']="#{IMAGEPATH}/bin:#{ENV['PATH']}"
    #SSLLIB = Fiddle::Handle.new(IMAGEPATH + "/lib/libopenssl.so", Fiddle::RTLD_LAZY | Fiddle::RTLD_GLOBAL)

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

    def dgst data, opts = {}
      opts = OpenStruct.new({dgst: 'dgst', engine: '-engine gost', dgst_arg: '-md_gost94'}.merge(opts.to_h))
      
      stdout, stderr, status = Open3.capture3("openssl #{opts[:dgst]} #{opts[:engine]} #{opts[:dgst_arg]} -binary", stdin_data: data, binmode: true)

      if status.success?
        return (Base64.encode64 stdout).strip
      else
        raise Error.new("dgst failed: #{stderr}")
      end
    end
      
    def sign key, data, opts = {}
      opts = OpenStruct.new({engine: '-engine gost'}.merge(opts.to_h))
      stdout, stderr, status = Open3.capture3("openssl dgst #{opts[:engine]} -sign #{key}", stdin_data: data, binmode: true)

      if status.success?
        return (Base64.strict_encode64 stdout.strip).strip
      else
        raise Error.new("sign failed: #{stderr}")
      end
    end

    def verify_file signature, file, opts = {}
      opts = OpenStruct.new({engine: '-engine gost'}.merge(opts.to_h))
      stdout, stderr, status = Open3.capture3("openssl smime -verify #{opts[:engine]} -noverify -inform DER -in #{signature} -content #{file}", binmode: true)

      if status.success?
        return /successful/ =~ stdout
      else
        raise Error.new("verify_file failed: #{stderr}")
      end
    end

    def sign_file key, cert, file, opts = {}
      opts = OpenStruct.new({engine: '-engine gost', sign_arg: '-gost89'}.merge(opts.to_h))
      stdout, stderr, status = Open3.capture3("openssl smime -sign #{opts[:engine]} #{opts[:sign_arg]}  -inkey #{key} -signer #{cert} -in #{file} -outform DER -binary", binmode: true)

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
    
    def sign_xml data, key, opts = {}
      opts = OpenStruct.new({engine: '-engine gost'}.merge(opts.to_h))
      puts "data to digest:#{data}"
      digest = self.dgst(data.canonicalize_excl, opts)  
      puts "DIGEST:#{digest}"
      
    template = <<-TEMPLATE
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
    <ds:Reference URI="##{data['ID']}">
      <ds:Transforms>
        <ds:Transform
          Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
      <ds:DigestValue></ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue></ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate></ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</ds:Signature>
TEMPLATE

      signature_structure = Nokogiri::XML::Document.parse(Nokogiri::XML::Document.parse(template, nil, "UTF-8").canonicalize_excl, nil, "UTF-8").children.first
      signed_info_structure = signature_structure.search_child("SignedInfo", NAMESPACES['ds']).first

      signed_info_structure.search_child("DigestValue", NAMESPACES['ds']).first.children = digest
      
      sign_value =  self.sign(key, signed_info_structure.canonicalize_excl, opts)
      signature_structure.search_child("SignatureValue", NAMESPACES['ds']).first.children = sign_value

      data << signature_structure
      data.to_xml(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML)
    end

    
    def verify_xml xml, opts = {}
      opts = OpenStruct.new({engine: '-engine gost'}.merge(opts.to_h))
      doc = Nokogiri::XML::Document.parse xml
      doc.search_child("Signature", NAMESPACES['ds']).each do |security|
        security.search_child("Reference", NAMESPACES['ds']).each { |ref| check_digest_impl doc, ref['URI'][1..-1], opts } 
        verify_signature_impl security, opts
      end
      return true
    end
    
    def check_digest_impl doc, ref, opts = {}
      opts = OpenStruct.new({engine: '-engine gost'}.merge(opts.to_h))
      data = doc.search("*[ID='#{ref}']").first
      if data
        tmpdata = Nokogiri::XML::Document.parse(data.to_xml(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML)).root
        signature = tmpdata.search_child("Signature", NAMESPACES['ds']).first.remove
        olddgst = signature.search_child("DigestValue", NAMESPACES['ds']).first.children.to_s.strip
        newdgst = self.dgst(tmpdata.canonicalize_excl, opts)
        raise Error.new("Wrong digest value: #{newdgst}") if newdgst != olddgst
      else
        raise Error.new("Not found signed partial!")
      end
    end
    
    def verify_signature_impl security, opts = {}
      opts = OpenStruct.new({engine: '-engine gost'}.merge(opts.to_h))
      certificate = "-----BEGIN CERTIFICATE-----\n"
      certificate << Base64.encode64(Base64.decode64(security.search_child("X509Certificate", NAMESPACES['ds']).first.children.to_s.strip))
      certificate << "-----END CERTIFICATE-----"

      
      stdout, stderr, status = Open3.capture3("openssl x509 #{opts[:engine]} -pubkey -noout", stdin_data: certificate, binmode: true)
      public_key_file = if status.success?
        SslGem::write_tmp stdout.strip
      else
        raise Error.new("pubkey extraction failed: #{stderr}")
      end
      
      signature_file = SslGem::write_tmp Base64.decode64(security.search_child("SignatureValue", NAMESPACES['ds']).first.children.to_s.strip)
      sig_info = security.search_child("SignedInfo", NAMESPACES['ds']).first.canonicalize_excl

      stdout, stderr, status = Open3.capture3("openssl dgst #{opts[:engine]} -verify " + public_key_file.path + ' -signature ' + signature_file.path, stdin_data: sig_info, binmode: true)
      if status.success?
        raise Error.new("Wrong signature!") unless /OK/ =~ stdout.strip
      else
        raise Error.new("pubkey extraction failed: #{stderr}")
      end
    ensure
      public_key_file.unlink if public_key_file
      signature_file.unlink  if signature_file
    end
    
    def self.write_tmp input, name = 'sign'
      tmp_file = Tempfile.new name
      tmp_file.binmode.write input
      tmp_file.close
      tmp_file
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



