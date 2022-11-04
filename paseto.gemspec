# frozen_string_literal: true

require_relative "lib/paseto/version"

Gem::Specification.new do |spec|
  spec.name = "paseto"
  spec.version = Paseto::Version::VERSION
  spec.authors = ["Joe Truba"]
  spec.email = ["joe@bannable.net"]

  spec.summary = "A toy implementation of PASETO v4"
  # spec.description = "TODO: Write a longer description or delete this line."
  spec.homepage = "https://github.com/bannable/paseto"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["allowed_push_host"] = "TODO: Set to your gem server 'https://example.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/bannable/paseto"
  spec.metadata["changelog_uri"] = "https://github.com/bannable/paseto"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  spec.add_dependency "rbnacl", "~> 7.1.1"

  spec.add_development_dependency "bundler"

  spec.metadata["rubygems_mfa_required"] = "true"
end
