# encoding: binary
# frozen_string_literal: true

module Paseto
  module V3
    class Local < Paseto::Key
      SHA384_DIGEST_LEN = 48
      NULL_SALT = 0.chr * SHA384_DIGEST_LEN

      def initialize(ikm:)
        @key = ikm
        super(version: "v3", purpose: "local")
      end

      def encrypt(message:, footer: "", implicit_assertion: "", n: nil) # rubocop:disable Naming/MethodParameterName
        raise ArgumentError, "no message" unless message

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

      def decrypt(token:, implicit_assertion: "")
        raise ArgumentError, "no token" unless token
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

      private

      attr_reader :key

      def calc_keys(nonce)
        ek, n2 = OpenSSL::KDF.hkdf(key, info: "paseto-encryption-key#{nonce}", salt: NULL_SALT, length: 48, hash: "SHA384").unpack("a32a16")
        ak = OpenSSL::KDF.hkdf(key, info: "paseto-auth-key-for-aead#{nonce}", salt: NULL_SALT, length: 48, hash: "SHA384")
        [ek, n2, ak]
      end

      def split_payload(payload)
        n = payload.slice(0, 32).to_s
        c = payload.slice(32, payload.size - 80).to_s
        t = payload.slice(-48, 48).to_s
        [n, c, t]
      end
    end
  end
end
