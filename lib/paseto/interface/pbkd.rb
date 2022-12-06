# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module PBKD
      extend T::Sig
      extend T::Helpers

      include Kernel

      abstract!

      module ClassMethods
        extend T::Sig
        extend T::Helpers

        interface!

        sig { abstract.returns(Interface::Version) }
        def protocol; end
      end

      mixes_in_class_methods(ClassMethods)

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
      def authenticate(header:, pre_key:, salt:, nonce:, edk:, params:); end

      sig { abstract.params(payload: String, key: String, nonce: String).returns(String) }
      def crypt(payload:, key:, nonce:); end

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

      sig(:final) { returns(Interface::Version) }
      def protocol
        self.class.protocol
      end

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
