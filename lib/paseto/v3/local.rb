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
      def protocol
        Protocol::Version3.new
      end

      # Symmetric encryption key
      sig(:final) { returns(String) }
      attr_reader :key

      # Create a new Local instance with a randomly generated key.
      sig(:final) { returns(T.attached_class) }
      def self.generate
        new(ikm: SecureRandom.random_bytes(32))
      end

      # `ikm` must be a 32-byte string
      sig(:final) { params(ikm: String).void }
      def initialize(ikm:)
        raise ArgumentError, 'ikm must be 32 bytes' unless ikm.bytesize == 32

        @key = ikm
      end

      # Encrypts and authenticates `message` with optional binding input `implicit_assertion`, returning a `Token`.
      # If `footer` is provided, it is included as authenticated data in the reuslting `Token``.
      # `n` must not be used outside of tests.
      sig(:final) { override.params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil) # rubocop:disable Naming/MethodParameterName
        n ||= SecureRandom.random_bytes(32)

        ek, n2, ak = calc_keys(n)

        c = protocol.crypt(payload: message, key: ek, nonce: n2)

        pre_auth = Util.pre_auth_encode(pae_header, n, c, footer, implicit_assertion)

        t = OpenSSL::HMAC.digest('SHA384', ak, pre_auth)

        Token.new(payload: "#{n}#{c}#{t}", version: version, purpose: purpose, footer: footer)
      end

      # Verify and decrypt an encrypted Token, with an optional string `implicit_assertion`, and return the plaintext.
      # If `token` includes a footer, it is treated as authenticated data to be verified but not returned.
      # `token` must be a `v3.local` type Token.
      sig(:final) { override.params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: '')
        raise LucidityError unless header == token.header

        n, c, t = split_payload(token.payload)

        ek, n2, ak = calc_keys(n)

        pre_auth = Util.pre_auth_encode(pae_header, n, c, token.footer, implicit_assertion)

        t2 = OpenSSL::HMAC.digest('SHA384', ak, pre_auth)

        raise InvalidAuthenticator unless Util.constant_compare(t, t2)

        protocol.crypt(payload: c, key: ek, nonce: n2).encode(Encoding::UTF_8)
      rescue Encoding::UndefinedConversionError
        raise ParseError, 'invalid payload encoding'
      end

      sig(:final) { override.returns(String) }
      def to_bytes
        key
      end

      private

      # Derive an encryption key, nonce, and authentication key from an input nonce.
      sig(:final) { params(nonce: String).returns([String, String, String]) }
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
      sig(:final) { params(payload: String).returns([String, String, String]) }
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
