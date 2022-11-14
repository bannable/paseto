# typed: strict
# frozen_string_literal: true

module Paseto
  module ISymmetric
    extend T::Sig
    extend T::Helpers

    include ICoder

    abstract!

    sig do
      override.params(
        payload: T::Hash[T.untyped, T.untyped],
        footer: String,
        implicit_assertion: String,
        n: T.nilable(String),
        json_options: T::Hash[T.untyped, T.untyped]
      ).returns(String)
    end
    def encode(payload:, footer: '', implicit_assertion: '', n: nil, json_options: {}) # rubocop:disable Naming/MethodParameterName
      message = MultiJson.dump(payload, json_options)
      encrypt(message:, footer:, implicit_assertion:, n:).to_s
    end

    sig do
      override.params(
        payload: String,
        implicit_assertion: String,
        json_options: T::Hash[T.untyped, T.untyped]
      ).returns(T::Hash[T.untyped, T.untyped])
    end
    def decode(payload:, implicit_assertion: '', json_options: {})
      token = Token.parse(payload)

      MultiJson.load(decrypt(token:, implicit_assertion:), json_options)
    end

    sig { abstract.params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
    def encrypt(message:, footer: '', implicit_assertion: '', n: nil); end # rubocop:disable Naming/MethodParameterName

    sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
    def decrypt(token:, implicit_assertion: ''); end
  end
end
