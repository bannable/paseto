# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module V4
    # PASETOv4 `local` token interface providing symmetric encryption of tokens.
    class Local < SymmetricKey
      extend T::Sig

      final!

      sig(:final) { override.returns(Protocol::Version4) }
      attr_reader :protocol

      # Create a new Local instance with a randomly generated key.
      sig(:final) { returns(T.attached_class) }
      def self.generate
        new(ikm: RbNaCl::Random.random_bytes(32))
      end

      sig(:final) { params(ikm: String).void }
      def initialize(ikm:)
        @protocol = T.let(Protocol::Version4.instance, Paseto::Protocol::Version4)

        super(ikm)
      end

      private

      # Derive an encryption key, nonce, and authentication key from an input nonce.
      sig(:final) { override.params(nonce: String).returns([String, String, String]) }
      def calc_keys(nonce)
        tmp = protocol.hmac("paseto-encryption-key#{nonce}", key: key, digest_size: 56)
        ek = T.must(tmp[0, 32])
        n2 = T.must(tmp[-24, 24])
        ak = protocol.hmac("paseto-auth-key-for-aead#{nonce}", key: key, digest_size: 32)
        [ek, n2, ak]
      end

      # Separate a token payload into:
      # - nonce, 32 leftmost bytes
      # - tag, 32 rightmost bytes
      # - ciphertext, everything in between
      sig(:final) { override.params(payload: String).returns([String, String, String]) }
      def split_payload(payload)
        n = T.must(payload.slice(0, 32))
        c = T.must(payload.slice(32, payload.size - 64))
        t = T.must(payload.slice(-32, 32))
        [n, c, t]
      rescue TypeError
        raise ParseError
      end
    end
  end
end
