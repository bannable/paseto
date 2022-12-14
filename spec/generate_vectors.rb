# typed: false
# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'erb'

def erb_for(name)
  ERB.new(File.read(File.join('vectors', 'templates', "#{name}_example.erb")), trim_mode: '-')
end

module Spec
  def example
    @template.result(binding)
  end
end

class LocalSpec
  include Spec

  attr_reader :name, :expect_fail, :nonce, :key, :token, :payload, :footer, :implicit_assertion

  def initialize(template_name, name:, expect_fail:, nonce:, key:, token:, payload:, footer:, implicit_assertion:, **_unused)
    @name = name
    @expect_fail = expect_fail
    @nonce = nonce
    @key = key
    @token = token
    @payload = payload
    @footer = footer
    @implicit_assertion = implicit_assertion
    @template = erb_for("#{template_name}_local")
  end
end

class PublicSpec
  include Spec

  attr_reader :name, :expect_fail, :public_key_pem, :secret_key_pem, :token, :payload, :footer, :implicit_assertion

  def initialize(template_name, name:, expect_fail:, public_key_pem:, secret_key_pem:, token:, payload:, footer:, implicit_assertion:,
                 **_unused)
    @name = name
    @expect_fail = expect_fail
    @public_key_pem = public_key_pem.inspect
    @secret_key_pem = secret_key_pem.inspect
    @token = token
    @payload = payload
    @footer = footer
    @implicit_assertion = implicit_assertion
    @template = erb_for("#{template_name}_public")
  end
end

class LocalWrapPieSpec
  include Spec

  attr_reader :name, :expect_fail, :unwrapped, :wrapping_key, :paserk

  def initialize(template_name, name:, expect_fail:, unwrapped:, wrapping_key:, paserk:, **_unused)
    @name = name
    @expect_fail = expect_fail
    @unwrapped = unwrapped
    @wrapping_key = wrapping_key
    @paserk = paserk
    @template = erb_for(template_name)
  end
end

class SecretWrapPieSpec
  include Spec

  attr_reader :name, :expect_fail, :unwrapped, :wrapping_key, :public_key, :paserk

  def initialize(template_name, name:, expect_fail:, unwrapped:, wrapping_key:, paserk:, public_key: nil, **_unused)
    @name = name
    @expect_fail = expect_fail
    @unwrapped = unwrapped
    @wrapping_key = wrapping_key
    @public_key = public_key
    @paserk = paserk
    @template = erb_for(template_name)
  end
end

class LocalPWSpec
  include Spec

  attr_reader :name, :expect_fail, :unwrapped, :password, :options, :paserk

  def initialize(template_name, name:, expect_fail:, unwrapped:, password:, options:, paserk:, **_unused)
    @name = name
    @expect_fail = expect_fail
    @unwrapped = unwrapped
    @password = password
    @options = options
    @paserk = paserk
    @template = erb_for(template_name)
  end
end

class SecretPWSpec
  include Spec

  attr_reader :name, :expect_fail, :unwrapped, :password, :options, :paserk

  def initialize(template_name, name:, expect_fail:, unwrapped:, password:, options:, paserk:, public_key: nil, **_unused)
    @name = name
    @expect_fail = expect_fail
    @unwrapped = unwrapped
    @password = password
    @options = options
    @public_key = public_key
    @paserk = paserk
    @template = erb_for(template_name)
  end
end

class IDSpec
  include Spec

  attr_reader :name, :expect_fail, :key, :paserk, :seed

  def initialize(template_name, name:, expect_fail:, key:, paserk:, seed: nil, **_unused)
    @name = name
    @expect_fail = expect_fail
    @paserk = paserk
    @key = key
    @seed = seed
    @template = erb_for(template_name)
  end
end

class SealSpec
  include Spec

  attr_reader :name, :expect_fail, :sealing_secret_key, :sealing_public_key, :unsealed, :paserk

  def initialize(template_name, name:, expect_fail:, sealing_secret_key:, sealing_public_key:, unsealed:, paserk:, **_unused)
    @name = name
    @expect_fail = expect_fail
    @paserk = paserk
    @sealing_secret_key = sealing_secret_key
    @sealing_public_key = sealing_public_key
    @unsealed = unsealed
    @template = erb_for(template_name)
  end
end

module SpecFactory
  def self.build(name, **test) # rubocop:disable Metrics/CyclomaticComplexity
    klass = case name
            when 'v3', 'v4'
              test.include?(:key) ? LocalSpec : PublicSpec
            when 'k3_local-wrap_pie', 'k4_local-wrap_pie' then LocalWrapPieSpec
            when 'k3_secret-wrap_pie', 'k4_secret-wrap_pie' then SecretWrapPieSpec
            when 'k3_local-pw', 'k4_local-pw' then LocalPWSpec
            when 'k3_secret-pw', 'k4_secret-pw' then SecretPWSpec
            when 'k3_lid', 'k3_pid', 'k3_sid', 'k4_lid', 'k4_pid', 'k4_sid' then IDSpec
            when 'k3_seal', 'k4_seal' then SealSpec
            else
              raise ArgumentError, "unrecognized vector: #{name}"
            end
    klass.new(name, **test)
  end
end

def generate(json_filename:, name:)
  json_path = File.join('vectors', 'json', json_filename)
  vectors = JSON.load_file(json_path)
  vectors['tests'].each do |t|
    t.transform_keys! { |k| k.tr('-', '_').to_sym }
  end

  outer_file = File.join('vectors', 'templates', 'outer.erb')
  outer_partial = ERB.new(File.read(outer_file), trim_mode: '-')

  specs = vectors['tests'].map { |t| SpecFactory.build(name, **t) }
                          .map(&:example).join("\n")

  file_path = File.join('vectors', "#{name}_spec.rb")
  FileUtils.mkdir_p File.dirname(file_path)
  FileUtils.rm file_path, force: true
  File.open(file_path, 'w') do |file|
    file.puts outer_partial.result(binding)
  end
end

if __FILE__ == $PROGRAM_NAME
  TEST_VECTORS = [
    { json_filename: 'v3.json', name: 'v3' },
    { json_filename: 'v4.json', name: 'v4' },
    { json_filename: 'k3.local-wrap.pie.json', name: 'k3_local-wrap_pie' },
    { json_filename: 'k3.secret-wrap.pie.json', name: 'k3_secret-wrap_pie' },
    { json_filename: 'k4.local-wrap.pie.json', name: 'k4_local-wrap_pie' },
    { json_filename: 'k4.secret-wrap.pie.json', name: 'k4_secret-wrap_pie' },
    { json_filename: 'k3.local-pw.json', name: 'k3_local-pw' },
    { json_filename: 'k3.secret-pw.json', name: 'k3_secret-pw' },
    { json_filename: 'k4.local-pw.json', name: 'k4_local-pw' },
    { json_filename: 'k4.secret-pw.json', name: 'k4_secret-pw' },
    { json_filename: 'k3.lid.json', name: 'k3_lid' },
    { json_filename: 'k4.lid.json', name: 'k4_lid' },
    { json_filename: 'k3.sid.json', name: 'k3_sid' },
    { json_filename: 'k4.sid.json', name: 'k4_sid' },
    { json_filename: 'k3.pid.json', name: 'k3_pid' },
    { json_filename: 'k4.pid.json', name: 'k4_pid' },
    { json_filename: 'k3.seal.json', name: 'k3_seal' },
    { json_filename: 'k4.seal.json', name: 'k4_seal' }
  ]

  TEST_VECTORS.each { |tv| generate(**tv) }
end
