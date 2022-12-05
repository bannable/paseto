# typed: false
# frozen_string_literal: true

module Paseto
  module Sodium
    class Curve25519
      extend T::Sig

      extend RbNaCl::Sodium

      sodium_type :sign
      sodium_primitive :ed25519

      sodium_function :to_x25519_private_key,
                      :crypto_sign_ed25519_sk_to_curve25519,
                      %i[pointer pointer]

      sodium_function :to_x25519_public_key,
                      :crypto_sign_ed25519_pk_to_curve25519,
                      %i[pointer pointer]

      sig { params(key: V4::Public).void }
      def initialize(key)
        @key = key
      end

      sig { returns(RbNaCl::PrivateKey) }
      def to_x25519_private_key
        buffer = RbNaCl::Util.zeros(RbNaCl::PrivateKey::BYTES)
        success = self.class.to_x25519_private_key(buffer, @key.to_bytes)
        raise CryptoError, 'Ed25519->X25519 sk failure' unless success

        RbNaCl::PrivateKey.new(buffer)
      end

      sig { returns(RbNaCl::PublicKey) }
      def to_x25519_public_key
        buffer = RbNaCl::Util.zeros(RbNaCl::PublicKey::BYTES)
        success = self.class.to_x25519_public_key(buffer, @key.public_bytes)
        raise CryptoError, 'Ed25519->X25519 pk failure' unless success

        RbNaCl::PublicKey.new(buffer)
      end
    end
  end
end
