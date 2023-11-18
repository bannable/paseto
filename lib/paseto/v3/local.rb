# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module V3
    # PASETOv3 `local` token interface providing symmetric encryption of tokens.
    class Local < SymmetricKey
      extend T::Sig
      extend T::Helpers

      # Size in bytes of a SHA384 digest
      SHA384_DIGEST_LEN = 48

      # String initialized to \x00 for use in key derivation
      NULL_SALT = T.let(0.chr * SHA384_DIGEST_LEN, String)

      final!

      sig(:final) { override.returns(Protocol::Version3) }
      attr_reader :protocol

      # Create a new Local instance with a randomly generated key.
      sig(:final) { returns(T.attached_class) }
      def self.generate
        new(ikm: SecureRandom.random_bytes(32))
      end

      sig(:final) { params(ikm: String).void }
      def initialize(ikm:)
        @protocol = T.let(Protocol::Version3.instance, Paseto::Protocol::Version3)

        super(ikm)
      end

      private

      # Derive an encryption key, nonce, and authentication key from an input nonce.
      sig(:final) { override.params(nonce: String).returns([String, String, String]) }
      def calc_keys(nonce)
        tmp = OpenSSL::KDF.hkdf(key, info: "paseto-encryption-key#{nonce}", salt: NULL_SALT, length: 48, hash: 'SHA384')
        ek = T.must(tmp[0, 32])
        n2 = T.must(tmp[-16, 16])
        ak = OpenSSL::KDF.hkdf(key, info: "paseto-auth-key-for-aead#{nonce}", salt: NULL_SALT, length: 48, hash: 'SHA384')
        [ek, n2, ak]
      end

      # Split `payload` into the following parts:
      # - nonce, 32 leftmost bytes
      # - tag, 48 rightmost bytes
      # - ciphertext, everything in between
      sig(:final) { override.params(payload: String).returns([String, String, String]) }
      def split_payload(payload)
        n = T.must(payload.slice(0, 32))
        c = T.must(payload.slice(32, payload.size - 80))
        t = T.must(payload.slice(-48, 48))
        [n, c, t]
      rescue TypeError
        raise ParseError
      end
    end
  end
end
