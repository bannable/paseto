# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module PBKD
      extend T::Sig
      extend T::Helpers

      abstract!

      sig do
        abstract.params(
          header: String,
          pre_key: String,
          salt: String,
          nonce: String,
          edk: String,
          params: T::Hash[Symbol, Integer]
        ).returns([String, String])
      end
      def authenticate(header:, pre_key:, salt:, nonce:, edk:, params:); end # rubocop:disable Metrics/ParameterLists

      sig(:final) { params(payload: String, key: String, nonce: String).returns(String) }
      def crypt(payload:, key:, nonce:)
        ek = protocol.digest("#{Operations::PBKW::DOMAIN_SEPARATOR_ENCRYPT}#{key}", digest_size: 32)

        protocol.crypt(key: ek, nonce:, payload:)
      end

      sig do
        abstract.params(payload: String).returns(
          {
            salt: String,
            nonce: String,
            edk: String,
            tag: String,
            params: T::Hash[Symbol, Integer]
          }
        )
      end
      def decode(payload); end

      sig { abstract.params(salt: String, params: T::Hash[Symbol, Integer]).returns(String) }
      def pre_key(salt:, params:); end

      sig(:final) { returns(String) }
      def paserk_version
        protocol.paserk_version
      end

      sig { abstract.returns(Interface::Version) }
      def protocol; end

      sig { abstract.returns(String) }
      def random_nonce; end

      sig { abstract.returns(String) }
      def random_salt; end

      sig(:final) { returns(String) }
      def version
        protocol.version
      end
    end
  end
end
