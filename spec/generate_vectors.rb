# frozen_string_literal: true

require 'json'

TEST_VECTORS = [
  { version: 'v4', path: 'vectors/v4.json' }
]

HEADER = <<HEADER
# frozen_string_literal: true

HEADER

OUTER_DESCRIBE = <<OUTER_DESCRIBE
RSpec.describe "%<vector_name>s" do
OUTER_DESCRIBE

class V4LocalSpec
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
  end

  def spec
    <<-SPEC
  it "#{name}" do
    nonce = Paseto::Util.decode_hex(%[#{nonce}])
    key = Paseto::Util.decode_hex(%[#{key}])
    tok = %[#{token}]
    payload = #{payload_or_nil}
    footer = %[#{footer}]
    ia = %[#{implicit_assertion}]
    token = Paseto::Token.parse(tok)
    local = Paseto::V4::Local.new(ikm: key)

#{expectations}
SPEC
  end
  
  def payload_or_nil
    return %(%[#{payload}]) if payload
    "nil"
  end

  def expectations
    if expect_fail
      <<-EXPECT
    enc = local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)
    expect(enc).to_not eq(token)

    expect { local.decrypt(token: token, implicit_assertion: ia) }.to raise_error(Paseto::InvalidAuthenticator)
  end
      EXPECT
    else
      <<-EXPECT
    expect(local.encrypt(message: payload, footer: footer, implicit_assertion: ia, n: nonce)).to eq(tok)

    expect(local.decrypt(token: token, implicit_assertion: ia)).to eq(payload)
  end
EXPECT
    end
  end
end

class V4PublicSpec
  attr_reader :name, :expect_fail, :public_key, :secret_key_seed, :token, :payload, :footer, :implicit_assertion

  def initialize(name:, expect_fail:, public_key:, secret_key_seed:, token:, payload:, footer:, implicit_assertion:, **_unused)
    @name = name
    @expect_fail = expect_fail
    @public_key = public_key
    @secret_key_seed = secret_key_seed
    @token = token
    @payload = payload
    @footer = footer
    @implicit_assertion = implicit_assertion
  end

  def spec
    <<-SPEC
  it "#{name}" do
    pub = Paseto::V4::Public.new(public_key: Paseto::Util.decode_hex(%[#{public_key}]))
    priv = Paseto::V4::Public.new(private_key: Paseto::Util.decode_hex(%[#{secret_key_seed}]))
    tok = %[#{token}]
    payload = #{payload_or_nil}
    footer = %[#{footer}]
    ia = %[#{implicit_assertion}]
    token = Paseto::Token.parse(tok)

#{expectations}
SPEC
  end

  def payload_or_nil
    return %(%[#{payload}]) if payload
    "nil"
  end

  def expectations
    if expect_fail
      <<-EXPECT
    signed = priv.sign(message: payload, footer: footer, implicit_assertion: ia)
    expect(signed).to_not eq(token)

    message = begin
                pub.verify(token: token, implicit_assertion: ia)
              rescue Paseto::InvalidSignature, Paseto::ParseError
                nil
              end
    expect(message).to be_nil
  end
      EXPECT
    else
      <<-EXPECT
    signed = priv.sign(message: payload, footer: footer, implicit_assertion: ia)
    expect(signed).to eq(tok)

    verify = pub.verify(token: token, implicit_assertion: ia)
    expect(verify).to eq(payload)

    verify = pub.verify(token: signed, implicit_assertion: ia)
    expect(verify).to eq(payload)
  end
EXPECT
    end
  end
end

module SpecFactory
  def self.generate(version, **test)
    case version
    when 'v4'
      if test.include?(:key)
        V4LocalSpec.new(**test)
      elsif test.include?(:public_key)
        V4PublicSpec.new(**test)
      else
        raise ArgumentError, "unrecognized test type: #{test}"
      end
    else
      raise ArgumentError, "unrecognized version: #{version}"
    end
  end
end

def generate_specs(version:, path:)
  vectors = JSON.load_file(path)
  vectors['tests'].each do |t|
    t.transform_keys! { |k| k.tr('-', '_').to_sym }
  end

  file_path = File.join("paseto", version, "test_vectors_spec.rb")
  File.unlink(file_path) if File.exist?(file_path)
  file = File.new(file_path, "w")
  file.puts HEADER
  file.puts sprintf(OUTER_DESCRIBE, vector_name: vectors['name'])
  vectors['tests'].each do |test|
    file.puts SpecFactory.generate(version, **test).spec
  end
  file.puts 'end'
  file.close
end

TEST_VECTORS.each { |tv| generate_specs(**tv) }
