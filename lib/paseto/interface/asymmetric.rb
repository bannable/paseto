# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Asymmetric
      extend T::Sig
      extend T::Helpers

      include Coder

      requires_ancestor { Key }

      abstract!

      sig(:final) do
        override.params(
          payload: T::Hash[String, T.untyped],
          footer: String,
          implicit_assertion: String,
          options: T.nilable(T.any(String, Integer, Symbol, T::Boolean))
        ).returns(String)
      end
      def encode(payload:, footer: '', implicit_assertion: '', **options)
        message = MultiJson.dump(payload, options)
        sign(message: message, footer: footer, implicit_assertion: implicit_assertion).to_s
      end

      sig(:final) do
        override.params(
          payload: String,
          implicit_assertion: String,
          options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
        ).returns(T::Hash[String, T.untyped])
      end
      def decode(payload:, implicit_assertion: '', **options)
        token = Token.parse(payload)

        MultiJson.load(verify(token: token, implicit_assertion: implicit_assertion), **options)
      end

      sig(:final) do
        override.params(
          payload: String,
          implicit_assertion: String,
          options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
        ).returns(T::Hash[String, T.untyped])
      end
      def decode!(payload:, implicit_assertion: '', **options)
        result = decode(**T.unsafe(payload: payload, implicit_assertion: implicit_assertion, **options))

        Verify.verify_claims(result, options)
      end

      sig(:final) { override.returns(String) }
      def purpose
        'public'
      end

      sig { abstract.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: ''); end

      sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: ''); end

      sig { abstract.returns(String) }
      def public_to_pem; end

      sig { abstract.returns(String) }
      def private_to_pem; end
    end
  end
end
