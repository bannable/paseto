# encoding: binary
# frozen_string_literal: true

module Paseto
  module V4
    class Local < Paseto::Key
      def initialize(ikm:)
        super(version: 'v4', purpose: 'local', ikm: ikm)
      end

      def encrypt(message:, footer: '', implicit_assertion: '')
        n = RbNaCl::Random.random_bytes(32)

        ek, n2 = RbNaCl::Hash.blake2b("paseto-encryption-key" + n, key: key, digest_size: 56).unpack('a32a24')

        ak = RbNaCl::Hash.blake2b("paseto-auth-key-for-aead" + n, key: key, digest_size: 32)

        c = Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(n2, message)

        pre_auth = Util.pre_auth_encode(header, n, c, footer, implicit_assertion)

        t = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        payload = Util.encode64(n + c + t)
        Token.new(payload: payload, version: version, purpose: purpose, footer: footer)
      end

      def decrypt(payload:, footer: '', implicit_assertion: '')
        raw = Util.decode64(payload)
        n = raw.slice(0, 32) || ''
        c = raw.slice(32, raw.size - 64) || ''
        t = raw.slice(-32, 32) || ''

        ek, n2 = RbNaCl::Hash.blake2b("paseto-encryption-key" + n, key: key, digest_size: 56).unpack('a32a24')

        ak = RbNaCl::Hash.blake2b("paseto-auth-key-for-aead" + n, key: key, digest_size: 32)

        pre_auth = Util.pre_auth_encode(header, n, c, footer, implicit_assertion)

        t2 = RbNaCl::Hash.blake2b(pre_auth, key: ak, digest_size: 32)

        raise InvalidAuthenticator unless Util.constant_compare(t, t2)

        Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(n2, c)
      end
    end
  end
end
