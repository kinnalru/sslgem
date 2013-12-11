#!/usr/bin/env ruby
require 'base64'
require 'pp'
require 'tree' 

$stderr.sync = true
$stdout.sync = true

puts "=============================="
puts "|       testing sslgem       |"
puts "=============================="

#certc = %x(openssl x509 -in ./cert.base -noout -text  -certopt no_pubkey -certopt no_sigdump)
#certc = certc.split("\n") if certc.class == String
#puts certc

class Tree::TreeNode
  
  def path(path, splitter = "/")
    p = path.split splitter
    return p.inject(self) {|h, el| (h) ? h[el] : nil}
  end
end


class Parser

  LINE=/^[ ]*(.*):$/  
  LINE1=/^[ ]*(.*): (.*)?$/
  LINE2=/^[ ]*(URI):(.*)?$/
  LINE3=/^[ ]*(.*)$/
  SKIP=/^.*:error:.*/
  
  def initialize params = {}
    @tab = params[:tab] || 4
    
    @depth = 0
    @hash = {}
    @root_node = Tree::TreeNode.new("ROOT", "Root Content")
    @stack = [@root_node]
  end
  
  def parse lines
    lines.each do |line|
      next if line.strip.empty?
      next if SKIP.match line
      parse_line line
    end
    
    hasher = lambda do |hash, e|
      hash[e.name.sub(" ", "_").downcase.to_sym] = e.content unless e.content.empty?
      e.children.each { |c|
        hasher.call(hash, c)
      }
      return hash
    end

    @hash = @root_node.children.each.inject({}) { |hash, c| hasher.call(hash, c)}
    @hash[:serial] = @root_node.path("Certificate/Data/Serial Number").children.first.name
    
    return @hash
  end
  
  def calc_depth line
    return line[/^[ ]*/].count("    ") / @tab
  end
  
  def parse_line line
    #puts "Parsing line: [#{line.strip}]"
    #puts "Stack Size Befor: #{@stack.size}"
    depth = calc_depth line
    if m = (LINE.match(line) || LINE1.match(line) || LINE2.match(line) || LINE3.match(line))
      key, value = [m[1], m[2]].map {|m| (m.nil?) ? "" : m.strip}
      puts "Key: [#{key}] Value: [#{value}]"
      
      if depth == @depth
        if @stack.last.path(key)
          @stack.last << Tree::TreeNode.new(key + "#{rand(100)}", value)
        else
          @stack.last << Tree::TreeNode.new(key, value)
        end
      elsif depth == @depth + 1
        parent = @stack.last.children.last || @stack.last
        parent << Tree::TreeNode.new(key, value)
        @stack.push parent
      elsif depth < @depth
        (@depth - depth).times do
          @stack.pop
        end
        parent = @stack.last
        parent[key] && key = key + " 2"
        parent << Tree::TreeNode.new(key, value)
      else
        puts "ERROR: [#{line}]"
      end

      @depth = depth
      #puts "Stack Size After: #{@stack.size}"
      #pp @root_node
    else
      puts "Error"
    end

  end

end

require 'nokogiri'

xml = Nokogiri.XML(File.read('/home/jerry2/devel/examples/real_request/real_response'))
xml.remove_namespaces!
certs = []
certs += xml.search('X509Certificate')
certs += xml.search('BinarySecurityToken')

def call_shell cmd, input
	open('| '+cmd, 'rb+:UTF-8') do |p|
		p.write input
		p.close_write
		p.read
	end
end

cert = "-----BEGIN CERTIFICATE-----#{certs.first.text}-----END CERTIFICATE-----"
osslcert = call_shell("openssl x509 -noout -text  -certopt no_pubkey -certopt no_sigdump", cert)
osslcert = osslcert.split("\n") if osslcert.class == String
puts osslcert

require 'openssl'

oc =  OpenSSL::X509::Certificate.new cert
puts oc.inspect

#parser = Parser.new
#pp parser.parse osslcert

exit 1

$:.unshift File.join(File.dirname(__FILE__))

puts ">> Loading gem..."
require 'sslgem'
puts ">> Loading gem...    OK"

puts "\n>> Creating ssl instance..."
ssl = SslGem.new
puts ">> Creating ssl instance... OK"


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
    sign = ssl.sign(SslGem::TESTKEY, "11111111") 
    puts "  >> Result OK #{sign}"
    
    puts "\n  >> Signing data 2..."
    sign = ssl.sign(SslGem::TESTKEY, "22222222")
    puts "  >> Result OK #{sign}"
    
    begin
        puts "\n  >> Signing data with invalid key..."
        sign = ssl.sign("/not/existent/key", "11111111")
        raise "it MUST be impossible to sign data"
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
        puts "\n  >> Verify invalid signature file..."
        ssl.verify_file(__FILE__, __FILE__) 
        raise "it must be impossible to verify this file"
    rescue SslGem::Error => e
        puts "  >> Result OK"
    end

    begin
        puts "\n  >> Verify BAD signature file..."
        File.write "/tmp/temp.test", "hello world"
        ssl.verify_file("/tmp/temp.sig", "/tmp/temp.test") 
        raise "it must be impossible to verify this file"
    rescue SslGem::Error => e
        puts "  >> Result OK"
    end
    
    puts "\n>> Test COMPLETED"

rescue => e
    puts "\n>> Test FAILED by exception:"
    puts e.inspect
end


