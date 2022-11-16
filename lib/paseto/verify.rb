# typed: strict
# frozen_string_literal: true

module Paseto
  class Verify
    class Verifiers < T::Enum
      extend T::Sig

      enums do
        Audience = new
        IssuedAt = new
        Issuer = new
        Expiration = new
        NotBefore = new
        Subject = new
        TokenIdentifier = new
      end

      sig { returns(T::Array[T.class_of(Validator)]) }
      def self.all
        values.each.map(&:verifier)
      end

      sig { returns(T.class_of(Validator)) }
      def verifier # rubocop:disable Metrics/CyclomaticComplexity
        case self
        when Audience then Paseto::Validator::Audience
        when IssuedAt then Paseto::Validator::IssuedAt
        when Issuer then Paseto::Validator::Issuer
        when Expiration then Paseto::Validator::Expiration
        when NotBefore then Paseto::Validator::NotBefore
        when Subject then Paseto::Validator::Subject
        when TokenIdentifier then Paseto::Validator::TokenIdentifier
        else
          # :nocov:
          T.absurd(self)
          # :nocov:
        end
      end
    end

    extend T::Sig

    sig do
      params(
        payload: T::Hash[String, T.untyped],
        options: T::Hash[Symbol, T.untyped]
      ).returns(T::Hash[T.untyped, T.untyped])
    end
    def self.verify_claims(payload, options = {})
      new(payload, Paseto.config.decode.to_h.merge(options)).verify_claims
    end

    sig { params(payload: T::Hash[String, T.untyped], options: T::Hash[Symbol, T.untyped]).void }
    def initialize(payload, options)
      @payload = payload
      @options = options
    end

    sig { returns(T::Hash[String, T.untyped]) }
    def verify_claims
      Verifiers.all.each { |v| v.new(@payload, @options).verify }
      @payload
    end
  end
end
