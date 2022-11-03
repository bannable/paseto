# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in paseto.gemspec
gemspec

gem "rake", "~> 13.0"
gem "rspec", "~> 3.0"

group :development do
  gem "rbs", require: false
end

group :test do
  gem "simplecov", "~> 0.21.2"
end

group :development, :test do
  gem "flay", require: false
  gem "flog", require: false
  gem "reek", require: false
  gem "steep", require: false
  gem "rubocop", "~> 1.38.0", require: false
  gem "rubocop-performance", "~> 1.15.0", require: false
  gem "rubocop-rake", "~> 0.6.0", require: false
  gem "rubocop-rspec", "~> 2.14.2", require: false
end
