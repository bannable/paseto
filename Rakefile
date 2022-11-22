# typed: ignore
# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

require 'rubocop/rake_task'

RuboCop::RakeTask.new

task default: %i[spec coverage:report]

namespace :coverage do
  task :report do
    require 'simplecov'

    SimpleCov.collate Dir['coverage/results/**/.resultset.json'] do
      enable_coverage :branch
    end
  end
end
