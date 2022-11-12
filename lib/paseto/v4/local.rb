# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module V4
    # PASETOv4 `local` token interface providing symmetric encryption of tokens.
    class Local < Paseto::Key
      # Symmetric encryption key
      sig { returns(String) }
      attr_reader :key

      # Create a new Local instance with a randomly generated key.
      sig { returns(Local) }
      def self.generate
        new(ikm: RbNaCl::Random.random_bytes(32))
      end

      # `ikm` must be a 32-byte string
      sig { params(ikm: String).void }
      def initialize(ikm:)
        @key = ikm
        super(version: 'v4', purpose: 'local')
      end

      # Encrypts and authenticates `message` with optional binding input `implicit_assertion`, returning a `Token`.
      # If `footer` is provided, it is included as authenticated data in the reuslting `Token``.
      # `n` must not be used outside of tests.
      sig { params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
      def encrypt(message:, footer: '', implicit_assertion: '', n: nil) # rubocop:disable Naming/MethodParameterName
        n ||= RbNaCl::Random.random_bytes(32)

        ek, n2, ak = calc_keys(n)

        c = Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(n2, message)

        pre_auth = Util.pre_auth_encode(pae_header, n, c, footer, implicit_assertion)

        t = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        Token.new(payload: (n + c + t), version:, purpose:, footer:)
      end

      # Verify and decrypt an encrypted Token, with an optional string `implicit_assertion`, and return the plaintext.
      # If `token` includes a footer, it is treated as authenticated data to be verified but not returned.
      # `token` must be a `v4.local` type Token.
      sig { params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: '') # rubocop:disable Metrics/AbcSize
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        # OPTIONAL: verify footer is expected, constant-time
        n, c, t = split_payload(token.payload)

        ek, n2, ak = calc_keys(n)

        pre_auth = Util.pre_auth_encode(pae_header, n, c, token.footer, implicit_assertion)

        t2 = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        raise InvalidAuthenticator unless Util.constant_compare(t, t2)

        Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(n2, c)
      end

      private

      # Separate a token payload into:
      # - nonce, 32 leftmost bytes
      # - tag, 32 rightmost bytes
      # - ciphertext, everything in between
      sig { params(payload: String).returns([String, String, String]) }
      def split_payload(payload)
        n = T.must(payload.slice(0, 32))
        c = T.must(payload.slice(32, payload.size - 64))
        t = T.must(payload.slice(-32, 32))
        [n, c, t]
      end

      # Derive an encryption key, nonce, and authentication key from an input nonce.
      sig { params(nonce: String).returns([String, String, String]) }
      def calc_keys(nonce)
        tmp = RbNaCl::Hash.blake2b("paseto-encryption-key#{nonce}", key:, digest_size: 56)
        ek = T.must(tmp[0, 32])
        n2 = T.must(tmp[-24, 24])
        ak = RbNaCl::Hash.blake2b("paseto-auth-key-for-aead#{nonce}", key:, digest_size: 32)
        [ek, n2, ak]
      end
    end
  end
end
