# typed: false
# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'erb'

def erb_for(name)
  ERB.new(File.read(File.join('vectors', 'templates', name + '_example.erb')), trim_mode: '-')
end

class Spec
  def example
    @template.result(binding)
  end
end

module V3
  class LocalSpec < Spec
    attr_reader :name, :expect_fail, :nonce, :key, :token, :payload, :footer, :implicit_assertion

    def initialize(name:, expect_fail:, nonce:, key:, token:, payload:, footer:, implicit_assertion:, **_unused)
      @name = name
      @expect_fail = expect_fail
      @nonce = nonce
      @key = key
      @token = token
      @payload = payload
      @footer = footer
      @implicit_assertion = implicit_assertion
      @template = erb_for('v3_local')
    end
  end

  class PublicSpec < Spec
    attr_reader :name, :expect_fail, :token, :payload, :footer, :implicit_assertion, :public_key, :secret_key, :public_key_pem,
                :secret_key_pem

    def initialize(name:, expect_fail:, public_key:, secret_key:, public_key_pem:, secret_key_pem:, token:, payload:, footer:,
                   implicit_assertion:, **_unused)
      @name = name
      @expect_fail = expect_fail
      @public_key = public_key
      @public_key_pem = public_key_pem.inspect
      @secret_key = secret_key
      @secret_key_pem = secret_key_pem.inspect
      @token = token
      @payload = payload
      @footer = footer
      @implicit_assertion = implicit_assertion
      @template = erb_for('v3_public')
    end
  end
end

module V4
  class LocalSpec < Spec
    attr_reader :name, :expect_fail, :nonce, :key, :token, :payload, :footer, :implicit_assertion

    def initialize(name:, expect_fail:, nonce:, key:, token:, payload:, footer:, implicit_assertion:, **_unused)
      @name = name
      @expect_fail = expect_fail
      @nonce = nonce
      @key = key
      @token = token
      @payload = payload
      @footer = footer
      @implicit_assertion = implicit_assertion
      @template = erb_for('v4_local')
    end
  end

  class PublicSpec < Spec
    attr_reader :name, :expect_fail, :public_key_pem, :secret_key_pem, :token, :payload, :footer, :implicit_assertion

    def initialize(name:, expect_fail:, public_key_pem:, secret_key_pem:, token:, payload:, footer:, implicit_assertion:, **_unused)
      @name = name
      @expect_fail = expect_fail
      @public_key_pem = public_key_pem.inspect
      @secret_key_pem = secret_key_pem.inspect
      @token = token
      @payload = payload
      @footer = footer
      @implicit_assertion = implicit_assertion
      @template = erb_for('v4_public')
    end
  end
end

module SpecFactory
  def self.build(name, **test)
    klass = case name
            when 'v4'
              if test.include?(:key)
                V4::LocalSpec
              elsif test.include?(:public_key)
                V4::PublicSpec
              else
                raise ArgumentError, "unrecognized test type: #{test}"
              end
            when 'v3'
              if test.include?(:key)
                V3::LocalSpec
              elsif test.include?(:public_key)
                V3::PublicSpec
              else
                raise ArgumentError, "unrecognized test type: #{test}"
              end
            else
              raise ArgumentError, "unrecognized version: #{version}"
            end
    klass.new(**test)
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
                          .map { |spec| spec.example }.join("\n")

  file_path = File.join('vectors', name + '_spec.rb')
  FileUtils.mkdir_p File.dirname(file_path)
  FileUtils.rm file_path, force: true
  File.open(file_path, 'w') do |file|
    file.puts outer_partial.result(binding)
  end
end

if __FILE__ == $PROGRAM_NAME
  TEST_VECTORS = [
    { json_filename: 'v4.json', name: 'v4' },
    { json_filename: 'v3.json', name: 'v3' },
    # { json_filename: 'k3.local-wrap.pie.json', name: 'k3_local-wrap_pie' }
  ]

  TEST_VECTORS.each { |tv| generate(**tv) }
end
