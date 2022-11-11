# typed: strict
# encoding: binary
# frozen_string_literal: true

module Paseto
  module V3
    class Local < Paseto::Key
      # Size in bytes of a SHA384 digest
      SHA384_DIGEST_LEN = 48

      NULL_SALT = T.let(0.chr * SHA384_DIGEST_LEN, String)

      sig { returns(String) }
      # Symmetric encryption key
      attr_reader :key

      sig { returns(Local) }
      def self.generate
        new(ikm: SecureRandom.random_bytes(32))
      end

      sig { params(ikm: String).void }
      def initialize(ikm:)
        @key = ikm
        super(version: "v3", purpose: "local")
      end

      # rubocop:disable Metrics/AbcSize
      sig { params(message: String, footer: String, implicit_assertion: String, n: T.nilable(String)).returns(Token) }
      def encrypt(message:, footer: "", implicit_assertion: "", n: nil) # rubocop:disable Naming/MethodParameterName
        n ||= SecureRandom.random_bytes(32)

        ek, n2, ak = calc_keys(n)

        cipher = OpenSSL::Cipher.new("aes-256-ctr").encrypt
        cipher.key = ek
        cipher.iv = n2
        c = cipher.update(message) + cipher.final

        pre_auth = Util.pre_auth_encode(pae_header, n, c, footer, implicit_assertion)

        t = OpenSSL::HMAC.digest("SHA384", ak, pre_auth)

        Token.new(payload: (n + c + t), version:, purpose:, footer:)
      end

      sig { params(token: Token, implicit_assertion: String).returns(String) }
      def decrypt(token:, implicit_assertion: "")
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        # OPTIONAL: verify footer is expected, constant-time
        n, c, t = split_payload(token.payload)

        ek, n2, ak = calc_keys(n)

        pre_auth = Util.pre_auth_encode(pae_header, n, c, token.footer, implicit_assertion)

        t2 = OpenSSL::HMAC.digest("SHA384", ak, pre_auth)

        raise InvalidAuthenticator unless Util.constant_compare(t, t2)

        cipher = OpenSSL::Cipher.new("aes-256-ctr").decrypt
        cipher.key = ek
        cipher.iv = n2
        cipher.update(c) + cipher.final
      end
      # rubocop:enable Metrics/AbcSize

      private

      sig { params(nonce: String).returns(T::Array[String]) }
      def calc_keys(nonce)
        tmp = OpenSSL::KDF.hkdf(key, info: "paseto-encryption-key#{nonce}", salt: NULL_SALT, length: 48, hash: "SHA384")
        ek = T.must(tmp[0, 32])
        n2 = T.must(tmp[-16, 16])
        ak = OpenSSL::KDF.hkdf(key, info: "paseto-auth-key-for-aead#{nonce}", salt: NULL_SALT, length: 48, hash: "SHA384")
        [ek, n2, ak]
      end

      sig { params(payload: String).returns([String, String, String]) }
      def split_payload(payload)
        n = T.must(payload.slice(0, 32))
        c = T.must(payload.slice(32, payload.size - 80))
        t = T.must(payload.slice(-48, 48))
        [n, c, t]
      end
    end
  end
end
