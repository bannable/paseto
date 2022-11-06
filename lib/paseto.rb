# encoding: binary
# frozen_string_literal: true

require "base64"
require "rbnacl"
require "securerandom"

require "paseto/sodium/stream/base"
require "paseto/sodium/stream/xchacha20_xor"

require "paseto/util"
require "paseto/version"
require "paseto/token"
require "paseto/key"

require "paseto/v4/local"

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
  
  include Version
end
