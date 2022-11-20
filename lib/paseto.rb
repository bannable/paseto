# encoding: binary
# typed: strict
# frozen_string_literal: true

require 'base64'
require 'multi_json'
require 'openssl'
require 'securerandom'
require 'sorbet-runtime'
require 'time'
require 'zeitwerk'

loader = Zeitwerk::Loader.for_gem
unless defined?(RbNaCl)
  loader.ignore(
    "#{__dir__}/paseto/v4/local.rb",
    "#{__dir__}/paseto/sodium/",
    "#{__dir__}/paseto/sodium.rb"
  )
end
loader.setup

module Paseto
  extend Configuration

  # Generic superclass for all Paseto errors
  class Error < StandardError; end

  # Deserialized data did not include mandatory fields.
  class ParseError < Error; end

  # Superclass for claim validation errors
  class ValidationError < Error; end

  # Token is expired
  class ExpiredToken < ValidationError; end

  # Token has a nbf before the current time
  class InactiveToken < ValidationError; end

  # Disallowed issuer
  class InvalidIssuer < ValidationError; end

  # Incorrect audience
  class InvalidAudience < ValidationError; end

  # Token issued in the future
  class ImmatureToken < ValidationError; end

  # Unacceptable sub
  class InvalidSubject < ValidationError; end

  # Missing or unacceptable jti
  class InvalidTokenIdentifier < ValidationError; end

  # A cryptographic primitive has failed for any reason,
  # such as attempting to initialize a stream cipher with
  # an invalid nonce.
  class CryptoError < Error; end

  # An authenticator was forged or otherwise corrupt
  class InvalidAuthenticator < CryptoError; end

  # A signature was forged or otherwise corrupt
  class InvalidSignature < CryptoError; end

  # A provided key parsed to a different algorithm than expected
  class IncorrectKeyType < CryptoError; end

  # Key is not valid for algorithm
  class InvalidKeyPair < CryptoError; end
end

loader.eager_load
