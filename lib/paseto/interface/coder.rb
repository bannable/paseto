# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Coder
      extend T::Sig
      extend T::Helpers

      interface!

      sig do
        abstract.params(
          payload: T::Hash[String, T.untyped],
          footer: String,
          implicit_assertion: String,
          options: T.untyped
        ).returns(String)
      end
      def encode(payload:, footer: '', implicit_assertion: '', options: {}); end

      sig do
        abstract.params(
          payload: String,
          implicit_assertion: String,
          options: T.untyped
        ).returns(T::Hash[String, T.untyped])
      end
      def decode(payload:, implicit_assertion: '', options: {}); end

      sig do
        abstract.params(
          payload: String,
          implicit_assertion: String,
          options: T.untyped
        ).returns(T::Hash[String, T.untyped])
      end
      def decode!(payload:, implicit_assertion: '', options: {}); end
    end
  end
end
