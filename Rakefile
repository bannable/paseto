# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

require "rubocop/rake_task"

RuboCop::RakeTask.new

task default: %i[spec rubocop steep:check]

namespace :steep do
  require "steep"
  require "steep/cli"

  task :check do
    Steep::CLI.new(argv: %w[check], stdout: $stdout, stderr: $stderr, stdin: $stdin).run
  end

  task :stats do
    Steep::CLI.new(argv: %w[stats], stdout: $stdout, stderr: $stderr, stdin: $stdin).run
  end
end
