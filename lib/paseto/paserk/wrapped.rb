# encoding: binary
# typed: true
# frozen_string_literal: true

module Paseto
  module Paserk
    class Wrapped
      extend T::Sig

      DOMAIN_SEPARATOR_AUTH = "\x81"
      DOMAIN_SEPARATOR_ENCRYPT = "\x80"

      sig { params(version: String, type: String, wrapping_key: String, data: String).returns(Key) }
      def self.unwrap(version, type, wrapping_key, data)
        new(version, type, wrapping_key, data).unwrap
      end

      sig { params(version: String, type: String, wrapping_key: String, data: String).void }
      def initialize(version, type, wrapping_key, data)
        @version = version
        @type = type
        @wrapping_key = wrapping_key
        @data = data
      end

      sig { returns(Key) }
      def unwrap
        decoded = decode_and_split

        ak = OpenSSL::HMAC.digest('SHA384', @wrapping_key, (DOMAIN_SEPARATOR_AUTH + decoded[:n])).byteslice(0, 32)
        t2 = OpenSSL::HMAC.digest('SHA384', ak, (pie_header + decoded[:n] + decoded[:c]))

        raise InvalidAuthenticator unless Util.constant_compare(decoded[:t], t2)

        ptk = decrypt_local(nonce: decoded[:n], ciphertext: decoded[:c])
        ptk = PKCS.p384_scalar_bytes_to_pkcs8_der(ptk) if @type == 'secret-wrap'

        PaserkTypes.deserialize(header).generate(ptk)
      end

      sig { returns(String) }
      def pie_header
        "#{header}.pie."
      end

      sig { returns(String) }
      def header
        "#{@version}.#{@type}"
      end

      private

      sig { returns({ t: String, n: String, c: String }) }
      def decode_and_split
        b = Util.decode64(@data)
        {
          t: T.must(b.byteslice(0, 48)),
          n: T.must(b.byteslice(48, 32)),
          c: T.must(b.byteslice(80..))
        }
      end

      sig { params(nonce: String, ciphertext: String).returns(String) }
      def decrypt_local(nonce:, ciphertext:)
        x = OpenSSL::HMAC.digest('SHA384', @wrapping_key, DOMAIN_SEPARATOR_ENCRYPT + nonce)
        ek = x[0, 32]
        n2 = x[32..]

        cipher = OpenSSL::Cipher.new('aes-256-ctr').decrypt
        cipher.key = ek
        cipher.iv = n2
        cipher.update(ciphertext) + cipher.final
      end
    end
  end
end
