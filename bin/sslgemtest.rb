#!/usr/bin/env ruby
require 'rubygems'
require 'base64'
require 'pp'

$stderr.sync = true
$stdout.sync = true

puts "=============================="
puts "|       testing sslgem       |"
puts "=============================="

#$:.unshift File.join(File.dirname(__FILE__))

puts ">> Loading gem..."
require 'sslgem'
puts ">> Loading gem...    OK"

puts "\n>> Creating ssl instance..."
ssl = Ssl::SslGem.new
puts ">> Creating ssl instance... OK"
puts ">>PATH: #{ENV['PATH']}"


puts ssl.info

puts ">> Begin test"
begin
    puts "\n  >> Generate digest 1..."
    dgst = ssl.dgst("11111111") 
    puts "  >> Result OK #{dgst}"
    
    puts "\n  >> Generate digest 2..."
    dgst = ssl.dgst("22222222")
    puts "  >> Result OK #{dgst}"
    

    puts "\n  >> Signing data 1..."
    sign = ssl.sign(Ssl::SslGem::TESTKEY, "11111111") 
    puts "  >> Result OK #{sign}"
    
    puts "\n  >> Signing data 2..."
    sign = ssl.sign(Ssl::SslGem::TESTKEY, "22222222")
    puts "  >> Result OK #{sign}"
    
    begin
        puts "\n  >> Signing data with invalid key..."
        sign = ssl.sign("/not/existent/key", "11111111")
        raise "it MUST be impossible to sign data"
    rescue Ssl::SslGem::Error => e
        puts "  >> Result OK"
    end
    

    puts "\n  >> Signing file..."
    sig = ssl.sign_file(Ssl::SslGem::TESTKEY, Ssl::SslGem::TESTCERT, __FILE__) 
    File.write "/tmp/temp.sig", sig
    puts "  >> Result OK"
    
    puts "\n  >> Verify signed file..."
    ssl.verify_file("/tmp/temp.sig", __FILE__) 
    puts "  >> Result OK"
    
    begin
        puts "\n  >> Verify invalid signature file..."
        ssl.verify_file(__FILE__, __FILE__) 
        raise "it must be impossible to verify this file"
    rescue Ssl::SslGem::Error => e
        puts "  >> Result OK"
    end

    begin
        puts "\n  >> Verify BAD signature file..."
        File.write "/tmp/temp.test", "hello world"
        ssl.verify_file("/tmp/temp.sig", "/tmp/temp.test") 
        raise "it must be impossible to verify this file"
    rescue Ssl::SslGem::Error => e
        puts "  >> Result OK"
    end
    
    
    puts "\n  >> Extracting certificates..."
    certs = ssl.extract_certs File.read(Ssl::SslGem::TESTRESPONSE)
	puts certs
    raise "Expected [1] certs occured [#{certs.size}]" if certs.size != 1
    raise "Not Before invalid" if certs.first.not_before.to_s != "2013-03-28 11:51:00 UTC"
    raise "Not After invalid" if certs.first.not_after.to_s !="2014-03-14 11:56:00 UTC"
    raise "Illegal extension extraction" if certs.first.extensions.inject({}) {|res, e| res[e.oid] = e.value; res}.keys.count != 9
    
    #openssl x509 -noout -text  -certopt no_pubkey -certopt no_sigdump
    
    puts "  >> Result OK"
    
    xml = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
  AssertionConsumerServiceURL="https://esia.s.rndsoft.ru/SOAP/ACS" 
  ForceAuthn="false" 
  ID="dsfgfs" 
  IsPassive="false" 
  IssueInstant="2014-02-19T10:58:59.236Z" 
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
  Version="2.0">
<samlp:Issuer xmlns:samlp="urn:oasis:names:tc:SAML:2.0:assertion">https://esia.s.rndsoft.ru/SOAP/ACS</samlp:Issuer>
</samlp:AuthnRequest>
XML

    puts "\n  >> Signing XML..."
    doc = Nokogiri::XML::Document.parse xml
    data = doc.search_child("AuthnRequest", NAMESPACES['samlp']).first
    result = ssl.sign_xml data, Ssl::SslGem::TESTKEY
    puts result.canonicalize_excl
    puts "  >> Result OK"

   
    puts "\n>> ALL Tests COMPLETED SUCCESFUL"

rescue => e
    puts "\n>> Test FAILED by exception:"
    puts e.inspect
end


