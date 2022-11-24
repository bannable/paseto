# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Paserk
    class PIE
      extend T::Sig

      DOMAIN_SEPARATOR_AUTH = "\x81"
      DOMAIN_SEPARATOR_ENCRYPT = "\x80"

      sig { params(version: String, type: String, wrapping_key: String, data: String).returns(Key) }
      def self.unwrap(version, type, wrapping_key, data)
        new(version, type, wrapping_key).unwrap(data)
      end

      sig { params(key: Key, wrapping_key: String, nonce: T.nilable(String)).returns(String) }
      def self.wrap(key, wrapping_key:, nonce: nil)
        version = key.version.sub('v', 'k')
        case key.purpose
        when 'public'
          type = 'secret-wrap'
        when 'local'
          type = 'local-wrap'
        else
          raise
        end

        new(version, type, wrapping_key).wrap(key, nonce)
      end

      sig { params(version: String, type: String, wrapping_key: String).void }
      def initialize(version, type, wrapping_key)
        @version = version
        @type = type
        @wrapping_key = wrapping_key
      end

      sig { params(data: String).returns(Key) }
      def unwrap(data)
        decode_and_split(data) => {n:, c:, t:}

        ak = OpenSSL::HMAC.digest('SHA384', @wrapping_key, (DOMAIN_SEPARATOR_AUTH + n)).byteslice(0, 32)
        t2 = OpenSSL::HMAC.digest('SHA384', ak, (pie_header + n + c))

        raise InvalidAuthenticator unless Util.constant_compare(t, t2)

        ptk = pie_crypt(nonce: n, payload: c)
        ptk = PKCS.p384_scalar_bytes_to_pkcs8_der(ptk) if @type == 'secret-wrap'

        PaserkTypes.deserialize(header).generate(ptk)
      end

      sig { params(key: Key, nonce: T.nilable(String)).returns(String) }
      def wrap(key, nonce)
        nonce ||= SecureRandom.bytes(32)

        c = pie_crypt(nonce: nonce, payload: key.to_bytes)

        ak = OpenSSL::HMAC.digest('SHA384', @wrapping_key, (DOMAIN_SEPARATOR_AUTH + nonce)).byteslice(0, 32)
        t = OpenSSL::HMAC.digest('SHA384', ak, (pie_header + nonce + c))

        pie_header + Util.encode64(t + nonce + c)
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

      sig { params(data: String).returns({ t: String, n: String, c: String }) }
      def decode_and_split(data)
        b = Util.decode64(data)
        {
          t: T.must(b.byteslice(0, 48)),
          n: T.must(b.byteslice(48, 32)),
          c: T.must(b.byteslice(80..))
        }
      end

      sig { params(nonce: String, payload: String).returns(String) }
      def pie_crypt(nonce:, payload:)
        x = OpenSSL::HMAC.digest('SHA384', @wrapping_key, DOMAIN_SEPARATOR_ENCRYPT + nonce)
        ek = x[0, 32]
        n2 = x[32..]

        cipher = OpenSSL::Cipher.new('aes-256-ctr').decrypt
        cipher.key = ek
        cipher.iv = n2
        cipher.update(payload) + cipher.final
      end
    end
  end
end
