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
          options: T.nilable(T.any(String, Integer, Symbol, T::Boolean))
        ).returns(String)
      end
      def encode(payload:, footer: '', implicit_assertion: '', **options)
        message = MultiJson.dump(payload, options)
        n = T.cast(options[:nonce], T.nilable(String))
        encrypt(message:, footer:, implicit_assertion:, n:).to_s
      end

      sig do
        override.params(
          payload: String,
          implicit_assertion: String,
          options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
        ).returns(T::Hash[String, T.untyped])
      end
      def decode(payload:, implicit_assertion: '', **options)
        token = Token.parse(payload)
        MultiJson.load(decrypt(token:, implicit_assertion:), **options)
      end

      sig do
        override.params(
          payload: String,
          implicit_assertion: String,
          options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
        ).returns(T::Hash[String, T.untyped])
      end
      def decode!(payload:, implicit_assertion: '', **options)
        result = decode(**T.unsafe({ payload:, implicit_assertion:, **options }))

        Verify.verify_claims(result, options)
      end

      sig { abstract.params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end # rubocop:disable Naming/MethodParameterName

      sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: ''); end
    end
  end
end
