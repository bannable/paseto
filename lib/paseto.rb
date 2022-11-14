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
require_relative 'paseto/token_validator'

require_relative 'paseto/key'
require_relative 'paseto/i_coder'
require_relative 'paseto/i_symmetric'
require_relative 'paseto/i_asymmetric'
require_relative 'paseto/v3/local'
require_relative 'paseto/v3/public'
require_relative 'paseto/v4/local'
require_relative 'paseto/v4/public'

module Paseto
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
end
