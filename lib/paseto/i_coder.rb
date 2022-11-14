# typed: strict
# frozen_string_literal: true

module Paseto
  module ICoder
    extend T::Sig
    extend T::Helpers

    interface!

    sig do
      abstract.params(
        payload: T::Hash[T.untyped, T.untyped],
        footer: String,
        implicit_assertion: String,
        n: T.nilable(String),
        json_options: T::Hash[T.untyped, T.untyped]
      ).returns(String)
    end
    def encode(payload:, footer: '', implicit_assertion: '', n: nil, json_options: {}); end # rubocop:disable Naming/MethodParameterName

    sig do
      abstract.params(
        payload: String,
        implicit_assertion: String,
        json_options: T::Hash[T.untyped, T.untyped]
      ).returns(T::Hash[T.untyped, T.untyped])
    end
    def decode(payload:, implicit_assertion: '', json_options: {}); end
  end
end
