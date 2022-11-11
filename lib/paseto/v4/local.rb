# typed: strict
# encoding: binary
# frozen_string_literal: true

module Paseto
  module V4
    class Local < Paseto::Key
      sig { returns(String) }
      # Symmetric encryption key
      attr_reader :key

      sig { returns(Local) }
      def self.generate
        new(ikm: RbNaCl::Random.random_bytes(32))
      end

      sig { params(ikm: String).void }
      def initialize(ikm:)
        @key = ikm
        super(version: "v4", purpose: "local")
      end

      sig { params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
      def encrypt(message:, footer: "", implicit_assertion: "", n: nil) # rubocop:disable Naming/MethodParameterName
        n ||= RbNaCl::Random.random_bytes(32)

        ek, n2, ak = calc_keys(n)

        c = Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(n2, message)

        pre_auth = Util.pre_auth_encode(pae_header, n, c, footer, implicit_assertion)

        t = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        Token.new(payload: (n + c + t), version:, purpose:, footer:)
      end

      sig { params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: "") # rubocop:disable Metrics/AbcSize
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        # OPTIONAL: verify footer is expected, constant-time
        n, c, t = split_payload(token.payload)

        ek, n2, ak = calc_keys(T.must(n))

        pre_auth = Util.pre_auth_encode(pae_header, n, c, token.footer, implicit_assertion)

        t2 = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        raise InvalidAuthenticator unless Util.constant_compare(t, t2)

        Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(n2, c)
      end

      private

      sig { params(payload: String).returns(T::Array[String]) }
      def split_payload(payload)
        n = payload.slice(0, 32).to_s
        c = payload.slice(32, payload.size - 64).to_s
        t = payload.slice(-32, 32).to_s
        [n, c, t]
      end

      sig { params(nonce: String).returns(T::Array[String]) }
      def calc_keys(nonce)
        tmp = RbNaCl::Hash.blake2b("paseto-encryption-key#{nonce}", key:, digest_size: 56)
        ek = T.cast(tmp[0, 32], String)
        n2 = T.cast(tmp[-24, 24], String)
        ak = RbNaCl::Hash.blake2b("paseto-auth-key-for-aead#{nonce}", key:, digest_size: 32)
        [ek, n2, ak]
      end
    end
  end
end
