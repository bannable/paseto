# encoding: binary
# typed: strict
# frozen_string_literal: true

require 'base64'
require 'multi_json'
require 'openssl'
require 'rbnacl'
require 'securerandom'
require 'sorbet-runtime'

require_relative 'paseto/sodium/stream/base'
require_relative 'paseto/sodium/stream/x_cha_cha20_xor'

require_relative 'paseto/util'
require_relative 'paseto/version'
require_relative 'paseto/token'
require_relative 'paseto/key'

require_relative 'paseto/v3/local'
require_relative 'paseto/v3/public'
require_relative 'paseto/v4/local'
require_relative 'paseto/v4/public'

module Paseto
  # Generic superclass for all Paseto errors
  class Error < StandardError; end

  # Deserialized data did not include mandatory fields.
  class ParseError < Error; end

  # A cryptographic primitive has failed for any reason,
  # such as attempting to initialize a stream cipher with
  # an invalid nonce.
  class CryptoError < Error; end

  # An authenticator was forged or otherwise corrupt
  class InvalidAuthenticator < CryptoError; end

  # A signature was forged or otherwise corrupt
  class InvalidSignature < CryptoError; end

  extend T::Sig

  include Version

  sig do
    params(
      payload: T.any(String, T::Hash[T.untyped, T.untyped]),
      key: T.any(Paseto::V4::Public, Paseto::V4::Local, Paseto::V3::Public, Paseto::V3::Local),
      footer: String,
      implicit_assertion: String,
      n: T.nilable(String)
    ).returns(String)
  end
  def self.encode(payload:, key:, footer: '', implicit_assertion: '', n: nil) # rubocop:disable Naming/MethodParameterName
    message = case payload
              when String
                payload
              when Hash
                MultiJson.dump(payload)
              end
    case key
    when Paseto::V3::Local, Paseto::V4::Local
      key.encrypt(message:, footer:, implicit_assertion:, n:).to_s
    when Paseto::V3::Public, Paseto::V4::Public
      key.sign(message:, footer:, implicit_assertion:).to_s
    end
  end

  sig do
    params(
      payload: String,
      key: T.any(Paseto::V4::Public, Paseto::V4::Local, Paseto::V3::Public, Paseto::V3::Local),
      implicit_assertion: String
    ).returns(T::Hash[T.untyped, T.untyped])
  end
  def self.decode(payload:, key:, implicit_assertion: '')
    token = Token.parse(payload)

    raise Paseto::ParseError, 'key not valid for given token type' unless key.is_a?(token.type)

    case key
    when Paseto::V3::Local, Paseto::V4::Local
      MultiJson.load(key.decrypt(token:, implicit_assertion:))
    when Paseto::V3::Public, Paseto::V4::Public
      MultiJson.load(key.verify(token:, implicit_assertion:))
    end
  end
end
