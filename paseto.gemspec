# frozen_string_literal: true

require_relative 'lib/paseto/version'

Gem::Specification.new do |spec|
  spec.name = 'ruby-paseto'
  spec.version = Paseto::VERSION
  spec.platform = Gem::Platform::RUBY
  spec.authors = ['Joe Truba']
  spec.email = ['joe@bannable.net']

  spec.summary = 'A ruby implementation of PASETO and PASERK tokens'
  spec.description = <<-DESCRIPTION
    Platform Agnostic SEcurity TOkens are a specification for secure stateless tokens.
    This is an implementation of PASETO tokens, and the PASERK key management extensions,
    in ruby, with runtime static type checking provided by Sorbet.
  DESCRIPTION
  spec.homepage = 'https://github.com/bannable/paseto'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.1.0'

  spec.metadata = {
    'bug_tracker_uri' => 'https://github.com/bannable/paseto/issues',
    'changelog_uri' => 'https://github.com/bannable/paseto/blob/main/CHANGELOG.md',
    'documentation_uri' => 'https://github.com/bannable/paseto',
    'homepage_uri' => 'https://github.com/bannable/paseto',
    'source_code_uri' => 'https://github.com/bannable/paseto',
    'rubygems_mfa_required' => 'true'
  }

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      f.match(/^(?:bin|spec|coverage|tmp|gemfiles)/) || # Irrelevant directories
        f.match(/^\.+/) || # Anything starting with .
        f.match(/^(Gemfile|Gemfile\.lock|Rakefile)$/) # Irrelevant files
    end
  end
  spec.require_paths = ['lib']

  spec.add_dependency 'multi_json', '~> 1.17'
  spec.add_dependency 'openssl', '>= 3.3', '< 5'
  spec.add_dependency 'sorbet-runtime'
  spec.add_dependency 'zeitwerk'
end
