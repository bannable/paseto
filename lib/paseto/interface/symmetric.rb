# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Symmetric
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
        n = T.cast(options[:nonce], T.nilable(String))
        encrypt(message: message, footer: footer, implicit_assertion: implicit_assertion, n: n).to_s
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
        MultiJson.load(decrypt(token: token, implicit_assertion: implicit_assertion), **options)
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
        'local'
      end

      sig(:final) { params(paserk: String).returns(Key) }
      def unwrap(paserk)
        Paserk.from_paserk(
          paserk: paserk,
          wrapping_key: T.cast(self, T.all(Paseto::Key, Interface::Symmetric))
        )
      end

      sig(:final) { params(key: Key, nonce: T.nilable(String)).returns(String) }
      def wrap(key, nonce: nil)
        Paserk.wrap(
          key: key,
          wrapping_key: T.cast(self, T.all(Paseto::Key, Interface::Symmetric)),
          nonce: nonce
        )
      end

      sig { abstract.params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end # rubocop:disable Naming/MethodParameterName

      sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: ''); end
    end
  end
end
