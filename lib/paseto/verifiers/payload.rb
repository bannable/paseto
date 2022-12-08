# typed: strict
# frozen_string_literal: true

module Paseto
  module Verifiers
    class Payload < T::Enum
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

      sig { params(body: T::Hash[String, T.untyped], options: T::Hash[Symbol, T.untyped]).void }
      def self.verify(body, options)
        values.each { |v| v.verifier.new(body, options).verify }
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
  end
end
