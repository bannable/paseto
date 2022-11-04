# encoding: binary
# frozen_string_literal: true

module Paseto
  module V4
    class Local < Paseto::Key::Base
      def initialize(ikm:)
        super(version: 'v4', purpose: 'local', ikm: ikm)
      end

      def encrypt(message:, footer: '', implicit_assertion: '')
        n = RbNaCl::Random.random_bytes(32)

        ek_n2 = RbNaCl::Hash.blake2b("paseto-encryption-key" + n, key: key, digest_size: 56)
        ek = ek_n2.byteslice(0, 32)
        n2 = ek_n2.byteslice(32, 56)

        ak = RbNaCl::Hash.blake2b("paseto-auth-key-for-aead" + n, key: key, digest_size: 32)

        c = RbNaCl::Stream::XChaCha20Xor.new(ek).encrypt(n2, message)
        pre_auth = Paseto.pre_auth_encode(header, n, c, footer, implicit_assertion)
        t = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        payload = Paseto.encode64(n + c + t)
        Token.new(payload: payload, version: version, purpose: purpose, footer: footer)
      end
    end
  end
end
