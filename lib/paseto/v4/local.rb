# encoding: binary
# frozen_string_literal: true

module Paseto
  module V4
    class Local < Paseto::Key
      def initialize(ikm:)
        @key = ikm
        super(version: "v4", purpose: "local")
      end

      def encrypt(message:, footer: "", implicit_assertion: "", n: nil) # rubocop:disable Naming/MethodParameterName
        n ||= RbNaCl::Random.random_bytes(32)

        ek, n2, ak = calc_keys(n)

        c = Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(n2, message)

        pre_auth = Util.pre_auth_encode(pae_header, n, c, footer, implicit_assertion)

        t = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        Token.new(payload: (n + c + t), version:, purpose:, footer:)
      end

      def decrypt(token:, implicit_assertion: "")
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

      def split_payload(payload)
        n = payload.slice(0, 32).to_s
        c = payload.slice(32, payload.size - 64).to_s
        t = payload.slice(-32, 32).to_s
        [n, c, t]
      end

      def calc_keys(nonce)
        # rubocop:disable Style/StringConcatenation
        ek, n2 = RbNaCl::Hash.blake2b("paseto-encryption-key" + nonce, key:, digest_size: 56).unpack("a32a24")
        ak = RbNaCl::Hash.blake2b("paseto-auth-key-for-aead" + nonce, key:, digest_size: 32)
        # rubocop:enable Style/StringConcatenation
        [ek, n2, ak]
      end

      attr_reader :key
    end
  end
end
