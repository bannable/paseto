# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PIE
      class Version3
        extend T::Sig

        include Interface::PIE

        DOMAIN_SEPARATOR_AUTH = "\x81"
        DOMAIN_SEPARATOR_ENCRYPT = "\x80"

        sig { params(wrapping_key: T.all(Key, Interface::Symmetric)).void }
        def initialize(wrapping_key)
          @wrapping_key = wrapping_key
        end

        sig { override.params(header: String, data: String).returns(String) }
        def decode(header, data)
          # :nocov:
          decode_and_split(data) => {t:, n:, c:}
          # :nocov:

          ak = OpenSSL::HMAC.digest('SHA384', @wrapping_key.to_bytes, (DOMAIN_SEPARATOR_AUTH + n)).byteslice(0, 32)
          t2 = OpenSSL::HMAC.digest('SHA384', ak, (header + n + c))

          raise InvalidAuthenticator unless Util.constant_compare(t, t2)

          crypt(nonce: n, payload: c)
        end

        sig { override.params(key: T.all(Paseto::Key, Paseto::V3::Version), nonce: T.nilable(String)).returns(String) }
        def encode(key, nonce)
          nonce ||= SecureRandom.bytes(32)

          h = pie_header(key)
          c = crypt(nonce: nonce, payload: key.to_bytes)

          ak = OpenSSL::HMAC.digest('SHA384', @wrapping_key.to_bytes, (DOMAIN_SEPARATOR_AUTH + nonce)).byteslice(0, 32)
          t = OpenSSL::HMAC.digest('SHA384', ak, (h + nonce + c))

          h + Util.encode64(t + nonce + c)
        end

        private

        sig { params(key: Key).returns(String) }
        def pie_header(key)
          case key
          when Interface::Symmetric then 'k3.local-wrap.pie.'
          when Interface::Asymmetric then 'k3.secret-wrap.pie.'
          else
            # :nocov:
            raise ArgumentError, 'not a valid type of key'
            # :nocov:
          end
        end

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
        def crypt(nonce:, payload:)
          x = OpenSSL::HMAC.digest('SHA384', @wrapping_key.to_bytes, DOMAIN_SEPARATOR_ENCRYPT + nonce)
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
end
