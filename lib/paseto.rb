# encoding: binary
# typed: strict
# frozen_string_literal: true

require 'base64'
require 'multi_json'
require 'openssl'
begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end
require 'securerandom'
require 'sorbet-runtime'
T::Configuration.enable_final_checks_on_hooks
require 'time'
require 'zeitwerk'

loader = Zeitwerk::Loader.for_gem
unless defined?(RbNaCl)
  loader.ignore(
    "#{__dir__}/paseto/v4/",
    "#{__dir__}/paseto/sodium/",
    "#{__dir__}/paseto/sodium.rb"
  )
end
loader.inflector.inflect(
  'asn1' => 'ASN1',
  'ec_private_key' => 'ECPrivateKey',
  'ecdsa_sig_value' => 'ECDSASigValue',
  'ecdsa_signature' => 'ECDSASignature',
  'ecdsa_full_r' => 'ECDSAFullR',
  'pie' => 'PIE',
  'pbkw' => 'PBKW',
  'pbkd' => 'PBKD',
  'id' => 'ID',
  'pke' => 'PKE'
)
loader.setup

module Paseto
  extend T::Sig
  extend Configuration

  HAS_RBNACL = T.let(!defined?(RbNaCl).nil?, T::Boolean)

  class Error < StandardError; end

  class AlgorithmError < Error; end
  # An algorithm assertion was violated, such as attempting to wrap a
  # v4 key with a v3 key, or providing an EC key other than secp384 to v3.
  class LucidityError < AlgorithmError; end

  # A cryptographic primitive has failed for any reason,
  # such as attempting to initialize a stream cipher with
  # an invalid nonce.
  class CryptoError < Error; end
  # An authenticator was forged or otherwise corrupt
  class InvalidAuthenticator < CryptoError; end
  # A signature was forged or otherwise corrupt
  class InvalidSignature < CryptoError; end
  # Key is not valid for algorithm
  class InvalidKeyPair < CryptoError; end

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
  # Footer contains unknown or forbidden payload types
  class InvalidWPK < ValidationError; end
  # Footer contains unknown or invalid KID payloads
  class InvalidKID < ValidationError; end

  class PaserkError < Error; end
  class UnknownProtocol < PaserkError; end
  class UnknownOperation < PaserkError; end

  # Deserialized data did not include mandatory fields.
  class ParseError < Error; end
  # Tried to work with a V4 token without RbNaCl loaded
  class UnsupportedToken < ParseError; end

  sig { returns(T::Boolean) }
  def self.rbnacl?
    !!defined?(RbNaCl)
  end
end

loader.eager_load
