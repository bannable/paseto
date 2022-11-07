# encoding: binary
# frozen_string_literal: true

module Paseto
  module V4
    class Local < Paseto::Key
      def initialize(ikm:)
        @key = ikm
        super(version: "v4", purpose: "local")
      end

      def encrypt(message:, footer: "", implicit_assertion: "", n: nil)
        n ||= RbNaCl::Random.random_bytes(32)

        ek, n2 = RbNaCl::Hash.blake2b("paseto-encryption-key" + n, key:, digest_size: 56).unpack("a32a24")

        ak = RbNaCl::Hash.blake2b("paseto-auth-key-for-aead" + n, key:, digest_size: 32)

        c = Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(n2, message)

        pre_auth = Util.pre_auth_encode("v4.local.", n, c, footer, implicit_assertion)

        t = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        Token.new(payload: (n + c + t), version:, purpose:, footer:)
      end

      def decrypt(token:, implicit_assertion: "")
        raise ParseError, "incorrect header for key type v4.local" unless header == token.header

        # OPTIONAL: verify footer is expected, constant-time
        payload = token.payload
        n = payload.slice(0, 32) || ""
        c = payload.slice(32, payload.size - 64) || ""
        t = payload.slice(-32, 32) || ""

        ek, n2 = RbNaCl::Hash.blake2b("paseto-encryption-key" + n, key:, digest_size: 56).unpack("a32a24")

        ak = RbNaCl::Hash.blake2b("paseto-auth-key-for-aead" + n, key:, digest_size: 32)

        pre_auth = Util.pre_auth_encode("v4.local.", n, c, token.footer, implicit_assertion)

        t2 = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        raise InvalidAuthenticator unless Util.constant_compare(t, t2)

        Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(n2, c)
      end

      private

      attr_reader :key
    end
  end
end
