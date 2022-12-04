# typed: false
# frozen_string_literal: true

module Paseto
  module Sodium
    class Curve25519
      extend RbNaCl::Sodium

      sodium_type :sign
      sodium_primitive :ed25519

      sodium_function :to_x25519_private_key,
                      :crypto_sign_ed25519_sk_to_curve25519,
                      %i[pointer pointer]

      sodium_function :to_x25519_public_key,
                      :crypto_sign_ed25519_pk_to_curve25519,
                      %i[pointer pointer]

      def initialize(key)
        @key = key
      end

      def to_x25519_private_key
        buffer = RbNaCl::Util.zeros(RbNaCl::Boxes::Curve25519XSalsa20Poly1305::PRIVATEKEYBYTES)
        success = self.class.to_x25519_private_key(buffer, @key.to_bytes)
        raise CryptoError, 'Ed25519->X25519 sk failure' unless success

        buffer
      end

      def to_x25519_public_key
        buffer = RbNaCl::Util.zeros(RbNaCl::Boxes::Curve25519XSalsa20Poly1305::PUBLICKEYBYTES)
        success = self.class.to_x25519_public_key(buffer, @key.public_bytes)
        raise CryptoError, 'Ed25519->X25519 pk failure' unless success

        buffer
      end
    end
  end
end
