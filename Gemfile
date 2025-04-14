# frozen_string_literal: true

source 'https://rubygems.org'

gemspec

group :development do
  # https://github.com/thoughtbot/appraisal/pull/205
  # Move back into the gemspec after Thoughtbot releases a fixed version
  gem 'appraisal', '~> 2', github: 'thoughtbot/appraisal', ref: 'b200e636903700098bef25f4f51dbc4c46e4c04c'

  gem 'bundler', '~> 2'
  gem 'debug', '>= 1.0'
  gem 'parlour'
  gem 'tapioca', '~> 0.16.11'
end

gem 'oj'
gem 'parallel_tests'
gem 'rake', '~> 13'
gem 'reek'
gem 'rspec', '~> 3'
gem 'rspec_junit_formatter'
gem 'rubocop', '~> 1.75', require: false
gem 'rubocop-performance', '~> 1.25', require: false
gem 'rubocop-rspec', '~> 3.5', require: false
gem 'rubocop-sorbet', '~> 0.10', require: false
gem 'simplecov', '~> 0'
gem 'simplecov_json_formatter'
gem 'sorbet', '~> 0'
gem 'timecop', '~> 0'
