# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "omniauth/openid_connect_two_phase/version"

Gem::Specification.new do |spec|
  spec.name          = "omniauth-openid-connect-two-phase"
  spec.version       = OmniAuth::OpenIDConnectTwoPhase::VERSION
  spec.authors       = ["SchoolKeep Inc.", "Mark Gangl", "Paris Yee"]
  spec.email         = ["dev@schoolkeep.com", "mark@schoolkeep.com", "paris@schoolkeep.com"]
  spec.summary       = %q{Two Phase OpenID Connect Strategy for Omniauth}
  spec.description   = %q{Two Phase OpenID Connect Strategy for Omniauth}
  spec.homepage      = "https://github.com/schoolkeep/omniauth-openid-connect-two-phase"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^spec/})
  spec.require_paths = ["lib"]

  spec.add_dependency "omniauth", '~> 1.1'
  spec.add_dependency "openid_connect", '1.3.0'
  spec.add_dependency "addressable", '~> 2.3'
  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake", "~> 10.0"
end
