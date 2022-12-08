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
      def encode(payload, footer: '', implicit_assertion: '', **options); end

      sig do
        abstract.params(
          payload: String,
          implicit_assertion: String,
          serializer: Interface::Deserializer,
          options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
        ).returns(Result)
      end
      def decode(payload, implicit_assertion: '', serializer: Paseto::Deserializer::Raw, **options); end

      sig { abstract.returns(String) }
      def pbkw_header; end

      sig { abstract.returns(Version) }
      def protocol; end

      sig { abstract.returns(String) }
      def purpose; end

      sig { abstract.returns(String) }
      def to_bytes; end

      sig { abstract.returns(String) }
      def to_paserk; end

      sig(:final) do
        params(
          payload: String,
          implicit_assertion: String,
          options: T.nilable(T.any(Proc, String, Integer, Symbol, T::Boolean))
        ).returns(Result)
      end
      def decode!(payload, implicit_assertion: '', **options)
        decode(payload, **T.unsafe(implicit_assertion: implicit_assertion, **options))
          .then { |result| Verify.verify(result, options) }
      end

      sig(:final) { returns({ 'exp' => String, 'iat' => String, 'nbf' => String }) }
      def default_claims
        now = Time.new
        {
          'exp' => (now + (60 * 60)).iso8601,
          'iat' => now.iso8601,
          'nbf' => now.iso8601
        }
      end

      sig(:final) { params(other: T.untyped).returns(T::Boolean) }
      def ==(other)
        self.class == other.class &&
          to_bytes == other.to_bytes
      end

      sig(:final) { returns(String) }
      def header = "#{version}.#{purpose}"

      sig(:final) { returns(String) }
      def paserk_version = protocol.paserk_version

      sig(:final) { returns(String) }
      def pae_header = "#{header}."

      sig(:final) { returns(String) }
      def version = protocol.version
    end
  end
end
