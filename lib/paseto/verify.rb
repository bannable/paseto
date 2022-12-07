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

    class FooterVerifiers < T::Enum
      extend T::Sig

      enums do
        ForbiddenWPKValue = new
        ForbiddenKIDValue = new
      end

      sig { params(footer: T::Hash[String, T.untyped], options: T::Hash[Symbol, T.untyped]).void }
      def self.verify(footer, options)
        values.each { |v| v.verifier.new(footer, options).verify }
      end

      sig { returns(T.class_of(Validator)) }
      def verifier
        case self
        when ForbiddenWPKValue then Paseto::Validator::WPK
        when ForbiddenKIDValue then Paseto::Validator::KeyID
        else
          T.absurd(self)
        end
      end
    end

    extend T::Sig

    sig { returns(Result) }
    attr_reader :result

    sig do
      params(
        result: Result,
        options: T::Hash[Symbol, T.untyped]
      ).returns(Verify)
    end
    def self.verify(result, options = {})
      new(result, Paseto.config.decode.to_h.merge(options))
        .then(&:verify_footer)
        .then(&:verify_claims)
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

    sig { returns(T.self_type) }
    def verify_claims
      PayloadVerifiers.verify(@result.body, @options)
      self
    end

    sig { returns(T.self_type) }
    def verify_footer
      FooterVerifiers.verify(@result.footer, @options) if @result.footer.is_a?(Hash)
      self
    end
  end
end
