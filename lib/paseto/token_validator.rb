# typed: strict
# frozen_string_literal: true

module Paseto
  class TokenValidator
    extend T::Sig

    sig { returns(T.nilable(String)) }
    attr_reader :iss, :aud

    sig { params(iss: T.nilable(String), aud: T.nilable(String)).void }
    def initialize(iss: nil, aud: nil)
      @iss = iss
      @aud = aud
    end

    sig { params(claims: T::Hash[T.untyped, T.untyped]).returns(T::Hash[T.untyped, T.untyped]) }
    def validate(claims)
      validate_iss(claims['iss'])
      validate_aud(claims['aud'])

      exp = T.cast(claims.fetch('exp', ''), String)
      nbf = T.cast(claims.fetch('nbf', ''), String)
      iat = T.cast(claims.fetch('iat', ''), String)

      validate_active(nbf:, exp:, iat:)
      claims
    end

    private

    sig { params(issuer: T.nilable(String)).void }
    def validate_iss(issuer)
      raise InvalidIssuer if iss && issuer != iss
    end

    sig { params(audience: T.nilable(String)).void }
    def validate_aud(audience)
      raise InvalidAudience if aud && audience != aud
    end

    sig { params(nbf: String, exp: String, iat: String).void }
    def validate_active(nbf:, exp:, iat:)
      now = Time.now
      raise ExpiredToken if now > Time.iso8601(exp)
      raise InactiveToken if now < Time.iso8601(nbf)
      raise FutureTokenError if now < Time.iso8601(iat)
    rescue ArgumentError => e
      raise ParseError, e.message
    end
  end
end
