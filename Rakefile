# typed: ignore
# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

require 'rubocop/rake_task'

RuboCop::RakeTask.new

desc 'Execute specs in parallel and generate a coverage report'
task default: %i[parallel coverage:report]

desc 'Execute specs non-parallel and generate a coverage report'
task specs: %i[spec coverage:report]

namespace :coverage do
  task :report do
    require 'simplecov'

    SimpleCov.collate Dir['coverage/results/**/.resultset.json'] do
      enable_coverage :branch
    end
  end
end

desc 'Execute specs in parallel'
task :parallel do
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
