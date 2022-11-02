# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in paseto.gemspec
gemspec

gem "rake", "~> 13.0"
gem "rspec", "~> 3.0"

group :development do
  gem "solargraph", require: false
end

group :test do
  gem "simplecov"
end

group :development, :test do
  gem "rubocop", require: false
  gem "rubocop-performance", require: false
  gem "rubocop-rake", require: false
  gem "rubocop-rspec", require: false
end
