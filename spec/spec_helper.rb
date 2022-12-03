# typed: false
# frozen_string_literal: true

require 'timecop'
require 'simplecov'

SimpleCov.start do
  if ENV['CI']
    require 'simplecov_json_formatter'
    formatter SimpleCov::Formatter::JSONFormatter
  elsif ENV['APPRAISAL_INITIALIZED']
    formatter SimpleCov::Formatter::SimpleFormatter
    gemfile = ENV.fetch('BUNDLE_GEMFILE', nil)
    coverage_dir "coverage/results/#{File.basename(gemfile, '.gemfile')}" if gemfile
  end

  enable_coverage :branch
end

require 'paseto'

Zeitwerk::Loader.eager_load_all

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.filter_run_excluding :sodium unless Paseto.rbnacl?
end
