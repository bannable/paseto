# typed: strict
# frozen_string_literal: true

module Paseto
  class SymmetricKey < Interface::Key
    extend T::Sig
    extend T::Helpers

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

    sig(:final) { override.returns(String) }
    def purpose
      'local'
    end

    sig(:final) { params(paserk: String).returns(Interface::Key) }
    def unwrap(paserk)
      Paserk.from_paserk(
        paserk: paserk,
        wrapping_key: self
      )
    end

    sig(:final) { params(key: Interface::Key, nonce: T.nilable(String)).returns(String) }
    def wrap(key, nonce: nil)
      Paserk.wrap(
        key: key,
        wrapping_key: self,
        nonce: nonce
      )
    end

    sig(:final) { override.returns(String) }
    def to_paserk
      "#{paserk_version}.#{purpose}.#{Util.encode64(to_bytes)}"
    end

    sig(:final) { returns(String) }
    def id
      Operations::ID.lid(self)
    end

    sig { abstract.params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
    def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end # rubocop:disable Naming/MethodParameterName

    sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
    def decrypt(token:, implicit_assertion: ''); end
  end
end
