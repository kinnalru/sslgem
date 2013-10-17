
class Helper
  def self.files(dir)
    d = Dir.new(dir)
    return (d.entries - [".", ".."]).map{|s| path = "#{d.path}/#{s}"; File.directory?(path) ? Helper::files(path).flatten + [path] : path}.flatten.sort
  rescue => e
    puts "Error: #{e}"
    return []
  end
end

Gem::Specification.new do |s|
    s.required_ruby_version = '~> 2.0'
    s.name        = 'sslgem'
    s.version     = '0.0.1'
    s.date        = '2010-04-28'
    s.summary     = "Simple and specific OpenSSL wrapper"
    s.description = "Simple and specific OpenSSL wrapper"
    s.authors     = ["jerry"]
    s.email       = 'kinnalru@gmail.com'
    s.bindir      = 'bin'
    s.executable  = 'sslgemtest.rb'
    s.files       = Helper::files('bin') + Helper::files('lib') + Helper::files('ext/ssl/')
    s.homepage    = 'http://ya.ru'
    s.license     = 'MIT'
    s.require_path= ['lib']
    s.extensions  = Dir['ext/ssl/extconf.rb']
end
