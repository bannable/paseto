# typed: strict
# frozen_string_literal: true

module Paseto
  class Verify
    class PayloadVerifiers < T::Enum
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
        result: Result,
        options: T::Hash[Symbol, T.untyped]
      ).returns(Result)
    end
    def self.verify_claims(result, options = {})
      new(result, Paseto.config.decode.to_h.merge(options)).verify_claims
    end

    sig do
      params(
        result: Result,
        options: T::Hash[Symbol, T.untyped]
      ).void
    end
    def initialize(result, options)
      @result = result
      @options = options
    end

    sig { returns(Result) }
    def verify_claims
      PayloadVerifiers.all.each { |v| v.new(@result.body, @options).verify }
      @result
    end
  end
end
