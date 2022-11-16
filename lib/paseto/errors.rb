# typed: strict
# frozen_string_literal: true

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
end
