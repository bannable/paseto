# encoding: binary
# typed: true
# frozen_string_literal: true

module Paseto
  module Interface
    class Key
      extend T::Sig
      extend T::Helpers

      DOMAIN_SEPARATOR_AUTH = "\x81"
      DOMAIN_SEPARATOR_ENCRYPT = "\x80"

      abstract!

      sig do
        abstract.params(
          payload: T::Hash[String, T.untyped],
          footer: String,
          implicit_assertion: String,
          options: T.any(String, Integer, Symbol, T::Boolean)
        ).returns(String)
      end
      def encode(payload:, footer: '', implicit_assertion: '', **options); end

      sig do
        abstract.params(
          payload: String,
          implicit_assertion: String,
          options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
        ).returns(T::Hash[String, T.untyped])
      end
      def decode(payload:, implicit_assertion: '', **options); end

      sig do
        abstract.params(
          payload: String,
          implicit_assertion: String,
          options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
        ).returns(T::Hash[String, T.untyped])
      end
      def decode!(payload:, implicit_assertion: '', **options); end

      sig { abstract.returns(String) }
      def purpose; end

      sig { abstract.returns(String) }
      def to_bytes; end

      sig { abstract.returns(String) }
      def to_paserk; end

      sig { abstract.returns(Version) }
      def protocol; end

      sig(:final) { returns(String) }
      def version
        protocol.version
      end

      sig(:final) { returns(String) }
      def paserk_version
        protocol.paserk_version
      end

      sig(:final) { returns(String) }
      def header
        "#{version}.#{purpose}"
      end

      sig(:final) { returns(String) }
      def pae_header
        "#{header}."
      end

      sig(:final) { params(other: T.untyped).returns(T::Boolean) }
      def ==(other)
        self.class == other.class &&
          to_bytes == other.to_bytes
      end
    end
  end
end