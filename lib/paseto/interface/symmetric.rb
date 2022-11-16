# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Symmetric
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
        encrypt(message:, footer:, implicit_assertion:, n: options[:nonce]).to_s
      end

      sig do
        override.params(
          payload: String,
          implicit_assertion: String,
          options: T.untyped
        ).returns(T::Hash[String, T.untyped])
      end
      def decode(payload:, implicit_assertion: '', **options)
        token = Token.parse(payload)
        MultiJson.load(decrypt(token:, implicit_assertion:), options)
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

      sig { abstract.params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end # rubocop:disable Naming/MethodParameterName

      sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: ''); end
    end
  end
end
