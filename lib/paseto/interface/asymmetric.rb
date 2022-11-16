# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Asymmetric
      extend T::Sig
      extend T::Helpers

      include Coder

      abstract!

      sig do
        override.params(
          payload: T::Hash[String, T.untyped],
          footer: String,
          implicit_assertion: String,
          options: T.untyped
        ).returns(String)
      end
      def encode(payload:, footer: '', implicit_assertion: '', **options)
        message = MultiJson.dump(payload, options)
        sign(message:, footer:, implicit_assertion:).to_s
      end

      sig do
        override.params(
          payload: String,
          implicit_assertion: String,
          options: T.untyped
        ).returns(T::Hash[String, T.untyped])
      end
      def decode(payload:, implicit_assertion: '', options: {})
        token = Token.parse(payload)

        MultiJson.load(verify(token:, implicit_assertion:), options)
      end

      sig do
        override.params(
          payload: String,
          implicit_assertion: String,
          options: T.untyped
        ).returns(T::Hash[String, T.untyped])
      end
      def decode!(payload:, implicit_assertion: '', options: {})
        result = decode(payload:, implicit_assertion:, options:)

        Verify.verify_claims(result, options)
      end

      sig { abstract.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: ''); end

      sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: ''); end
    end
  end
end
