
class Helper
  def self.files(dir)
    d = Dir.new(dir)
    return (d.entries - [".", ".."]).map{|s| path = "#{d.path}/#{s}"; Dir.exist?(path) ? Helper::files(path).flatten + [path] : path}.flatten.sort
  rescue
    return []
  end
end

Gem::Specification.new do |s|
    s.name        = 'sslgem'
    s.version     = '0.0.1'
    s.date        = '2010-04-28'
    s.summary     = "Simple and specific OpenSSL wrapper"
    s.description = "Simple and specific OpenSSL wrapper"
    s.authors     = ["jerry"]
    s.email       = 'kinnalru@gmail.com'
    s.files       = Helper::files("lib")
    s.homepage    = 'http://ya.ru'
    s.license     = 'MIT'
end
