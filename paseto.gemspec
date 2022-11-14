# frozen_string_literal: true

require_relative "lib/paseto/version"

Gem::Specification.new do |spec|
  spec.name = "paseto"
  spec.version = Paseto::Version::VERSION
  spec.authors = ["Joe Truba"]
  spec.email = ["joe@bannable.net"]

  spec.summary = "A ruby implementation of PASETO tokens"
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
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci|devcontainer|vscode|github|solargraph\.yml)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  spec.add_runtime_dependency "ffi", "~> 1"
  spec.add_runtime_dependency "openssl", "~> 3.0.0"
  spec.add_runtime_dependency "multi_json", "~> 1.15.0"
  spec.add_runtime_dependency "rbnacl", "~> 7.1.1"
  spec.add_runtime_dependency "securerandom"
  spec.add_runtime_dependency "sorbet-runtime"

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "debug", ">= 1.0"
  spec.add_development_dependency "parlour"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "reek"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.38.0"
  spec.add_development_dependency "rubocop-performance", "~> 1.15.0"
  spec.add_development_dependency "rubocop-rspec", "~> 2.14.2"
  spec.add_development_dependency "rubocop-sorbet", "~> 0.6.11"
  spec.add_development_dependency "simplecov", "~> 0.21.2"
  spec.add_development_dependency "sorbet"
  spec.add_development_dependency "tapioca"
  spec.add_development_dependency "unparser"

  spec.metadata["rubygems_mfa_required"] = "true"
end
