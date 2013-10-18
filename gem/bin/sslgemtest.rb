#!/usr/bin/env ruby
#
require 'base64'

$stderr.sync = true
$stdout.sync = true

puts "=============================="
puts "|       testing sslgem       |"
puts "=============================="

$:.unshift File.join(File.dirname(__FILE__))

puts ">> Loading gem..."
require 'sslgem'
puts ">> Loading gem...    OK"

puts "\n>> Creating ssl instance..."
ssl = SslGem.new
puts ">> Creating ssl instance... OK"

puts ">> Begin test"
begin

	puts "\n >> Create digest 1...."
    dgst = ssl.dgst("11111111") 
    puts "  >> Result OK #{dgst}"

	puts "\n >> Create digest 2...."
    dgst = ssl.dgst("22222222") 
    puts "  >> Result OK #{dgst}"
    
    puts "\n  >> Generate sign 1..."
    sign = ssl.sign(SslGem::TESTKEY, "11111111") 
    puts "  >> Result OK #{sign}"
    
    puts "\n  >> Generate sign 2..."
    sign = ssl.sign(SslGem::TESTKEY, "22222222")
    puts "  >> Result OK #{dgst}"
    
    begin
        puts "\n  >> Generate sign with invalid key..."
        sign = ssl.sign("/not/existent/key", "11111111")
        raise "it must be impossible to generate digest"
    rescue SslGem::Error => e
        puts "  >> Result OK"
    end
    
    
    puts "\n  >> Signing file..."
    sig = ssl.sign_file(SslGem::TESTKEY, SslGem::TESTCERT, __FILE__) 
    File.write "/tmp/temp.sig", sig
    puts "  >> Result OK"
    
    puts "\n  >> Verify signed file..."
    ssl.verify_file("/tmp/temp.sig", __FILE__) 
    puts "  >> Result OK"
    
    begin
        puts "\n  >> Verify BAD signed file..."
        ssl.verify_file(__FILE__, __FILE__) 
        raise "it must be impossible to verify this file"
    rescue SslGem::Error => e
        puts "  >> Result OK"
    end
    
    puts "\n>> Test COMPLETED"

rescue => e
    puts "\n>> Test FAILED by exception:"
    puts e.inspect
end


