version = File.open(File.dirname(__FILE__) + '/VERSION', 'r').read.strip

Gem::Specification.new do |gem|
  gem.name = "oa-ldap"
  gem.version = version
  gem.summary = %Q{LDAP strategies for OmniAuth.}
  gem.description = %Q{LDAP strategies for OmniAuth.}
  gem.email = "pedro.t@gmail.com"
  gem.homepage = "http://github.com/pedroteixeira/oa-ldap"
  gem.authors = ["Pedro Teixeira"]
  
  gem.files = Dir.glob("{lib}/**/*") + %w(README.rdoc LICENSE.rdoc CHANGELOG.rdoc)
  
  gem.add_dependency 'oa-core',  '>= 0.0.3'
  gem.add_dependency 'net-ldap', '>= 0.1.1'
  gem.add_dependency 'jruby-ldap', '>= 0.0.1'
end
