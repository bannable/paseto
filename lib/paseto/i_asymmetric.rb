# typed: strict
# frozen_string_literal: true

module Paseto
  module IAsymmetric
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
    def encode(payload:, footer: '', implicit_assertion: '', n: nil, json_options: {}) # rubocop:disable Naming/MethodParameterName, Metrics/ParameterLists
      message = MultiJson.dump(payload, json_options)
      sign(message:, footer:, implicit_assertion:).to_s
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

      MultiJson.load(verify(token:, implicit_assertion:), json_options)
    end

    sig { abstract.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
    def sign(message:, footer: '', implicit_assertion: ''); end

    sig { abstract.params(token: Token, implicit_assertion: String).returns(String) }
    def verify(token:, implicit_assertion: ''); end
  end
end
