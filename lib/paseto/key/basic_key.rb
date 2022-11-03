# encoding: binary
# frozen_string_literal: true

module Paseto
  module Key
    class BasicKey
      HEADER = 'invalid'

      def initialize(ikm:, version:)
        @material = ikm
        @version = version
      end

      def valid_for?(version:, purpose:)
        purpose == valid_purpose && version == @version
      end

      def valid_purpose
        raise NotImplementedError
      end

      def self.header
        self.const_get(:HEADER)
      end

      def header
        self.class.header
      end

      def encrypt(payload:, footer: '', implicit_assertion: '')
        n = RbNaCl::Random.random_bytes(32)

        ek_n2 = RbNaCl::Hash.blake2b("paseto-encryption-key" + n, key: @material, digest_size: 56)
        ek = ek_n2.byteslice(0, 32)
        n2 = ek_n2.byteslice(32, 56)

        ak = RbNaCl::Hash.blake2b("paseto-auth-key-for-aead" + n, key: @material, digest_size: 32)

        c = RbNaCl::Stream::XChaCha20Xor.new(ek).encrypt(n2, payload)
        pre_auth = Paseto.pre_auth_encode(header, n, c, footer, implicit_assertion)
        t = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        payload = Paseto.encode64(n + c + t)
        Token.new(header: header, payload: payload, footer: footer)
      end
    end
  end
end
