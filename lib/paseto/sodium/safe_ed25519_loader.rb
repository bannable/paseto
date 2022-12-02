# typed: strict
# frozen_string_literal: true

module Paseto
  module Sodium
    module SafeEd25519Loader
      extend T::Sig

      include Kernel

      sig(:final) { params(keypair: String).returns(RbNaCl::SigningKey) }
      def self.from_keypair(keypair)
        RbNaCl::SigningKey.new(keypair[0, 32]).tap do |key|
          raise InvalidKeyPair, 'public key does not match private' unless keypair == key.keypair_bytes
        end
      end
    end
  end
end
