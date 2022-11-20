# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module V3
    # PASETOv3 `local` token interface providing symmetric encryption of tokens.
    class Local < Paseto::Key
      include Interface::Symmetric

      # Size in bytes of a SHA384 digest
      SHA384_DIGEST_LEN = 48

      # String initialized to \x00 for use in key derivation
      NULL_SALT = T.let(0.chr * SHA384_DIGEST_LEN, String)

      # Symmetric encryption key
      sig { returns(String) }
      attr_reader :key

      # Create a new Local instance with a randomly generated key.
      sig { returns(T.attached_class) }
      def self.generate
        new(ikm: SecureRandom.random_bytes(32))
      end

      # `ikm` must be a 32-byte string
      sig { params(ikm: String).void }
      def initialize(ikm:)
        @key = ikm
        super(version: 'v3', purpose: 'local')
      end

      # rubocop:disable Metrics/AbcSize

      # Encrypts and authenticates `message` with optional binding input `implicit_assertion`, returning a `Token`.
      # If `footer` is provided, it is included as authenticated data in the reuslting `Token``.
      # `n` must not be used outside of tests.
      sig { override.params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil) # rubocop:disable Naming/MethodParameterName
        n ||= SecureRandom.random_bytes(32)

        ek, n2, ak = calc_keys(n)

        cipher = OpenSSL::Cipher.new('aes-256-ctr').encrypt
        cipher.key = ek
        cipher.iv = n2
        c = cipher.update(message.encode(Encoding::UTF_8)) + cipher.final

        pre_auth = Util.pre_auth_encode(pae_header, n, c, footer, implicit_assertion)

        t = OpenSSL::HMAC.digest('SHA384', ak, pre_auth)

        Token.new(payload: (n + c + t), version:, purpose:, footer:)
      end

      # Verify and decrypt an encrypted Token, with an optional string `implicit_assertion`, and return the plaintext.
      # If `token` includes a footer, it is treated as authenticated data to be verified but not returned.
      # `token` must be a `v3.local` type Token.
      sig { override.params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: '')
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        n, c, t = split_payload(token.payload)

        ek, n2, ak = calc_keys(n)

        pre_auth = Util.pre_auth_encode(pae_header, n, c, token.footer, implicit_assertion)

        t2 = OpenSSL::HMAC.digest('SHA384', ak, pre_auth)

        raise InvalidAuthenticator unless Util.constant_compare(t, t2)

        cipher = OpenSSL::Cipher.new('aes-256-ctr').decrypt
        cipher.key = ek
        cipher.iv = n2
        plaintext = cipher.update(c) + cipher.final
        plaintext.encode(Encoding::UTF_8)
      rescue Encoding::UndefinedConversionError
        raise ParseError, 'invalid payload encoding'
      end
      # rubocop:enable Metrics/AbcSize

      private

      # Derive an encryption key, nonce, and authentication key from an input nonce.
      sig { params(nonce: String).returns([String, String, String]) }
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
      sig { params(payload: String).returns([String, String, String]) }
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
