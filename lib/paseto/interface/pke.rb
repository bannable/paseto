# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module PKE
      extend T::Sig
      extend T::Helpers

      include Kernel

      abstract!

      DOMAIN_SEPARATOR_ENCRYPT = "\x01"
      DOMAIN_SEPARATOR_AUTH = "\x02"

      module ClassMethods
        extend T::Sig
        extend T::Helpers

        interface!

        sig { abstract.params(esk: T.untyped).returns(String) }
        def epk_bytes_from_esk(esk); end

        sig { abstract.returns(T.untyped) }
        def generate_ephemeral_key; end

        sig { abstract.returns(String) }
        def header; end

        sig { abstract.returns(Interface::Version) }
        def protocol; end

        sig { abstract.params(encoded_data: String).returns([String, T.untyped, String]) }
        def split(encoded_data); end
      end

      mixes_in_class_methods(ClassMethods)

      sig { abstract.returns(AsymmetricKey) }
      def sealing_key; end

      sig { abstract.params(xk: String, epk: T.untyped).returns(String) }
      def derive_ak(xk:, epk:); end

      sig { abstract.params(xk: String, epk: T.untyped).returns({ ek: String, n: String }) }
      def derive_ek_n(xk:, epk:); end

      sig { abstract.params(message: String, ek: String, n: String).returns(SymmetricKey) }
      def decrypt(message:, ek:, n:); end

      sig { abstract.params(message: String, ek: String, n: String).returns(String) }
      def encrypt(message:, ek:, n:); end

      sig { abstract.params(ak: String, epk: T.untyped, edk: String).returns(String) }
      def tag(ak:, epk:, edk:); end

      sig(:final) { params(esk: T.untyped).returns(String) }
      def epk_bytes_from_esk(esk)
        self.class.epk_bytes_from_esk(esk)
      end

      sig(:final) { returns(T.untyped) }
      def generate_ephemeral_key
        self.class.generate_ephemeral_key
      end

      sig(:final) { returns(String) }
      def header
        self.class.header
      end

      sig(:final) { returns(Interface::Version) }
      def protocol
        self.class.protocol
      end

      sig(:final) { params(encoded_data: String).returns([String, T.untyped, String]) }
      def split(encoded_data)
        self.class.split(encoded_data)
      end
    end
  end
end
