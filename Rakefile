# typed: ignore
# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

require 'rubocop/rake_task'

RuboCop::RakeTask.new

task default: %i[parallel:spec coverage:report]

namespace :coverage do
  task :report do
    require 'simplecov'

    SimpleCov.collate Dir['coverage/results/**/.resultset.json'] do
      enable_coverage :branch
    end
  end
end

namespace :parallel do
  task :spec do
    command = [
      'bin/parallel_rspec',
      '--highest-exit-status',
      '--serialize-stdout',
      '--verbose-command',
      '--combine-stderr'
    ]

    if ENV['APPRAISAL_INITIALIZED']
      appraisal = File.basename(ENV.fetch('BUNDLE_GEMFILE'), '.gemfile')
      logpath = "tmp/#{appraisal}_parallel_runtime_rspec.log"
    else
      logpath = 'tmp/parallel_runtime_rspec.log'
    end
    command << ['-o', "-f p -f ParallelTests::RSpec::RuntimeLogger --out #{logpath}"]
    abort unless system(*command.flatten)
  end
end
