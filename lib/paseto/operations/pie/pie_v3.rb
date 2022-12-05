# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PIE
      class PieV3
        extend T::Sig

        include Interface::PIE

        DOMAIN_SEPARATOR_AUTH = "\x81"
        DOMAIN_SEPARATOR_ENCRYPT = "\x80"

        sig { override.returns(Protocol::Version3) }
        def self.protocol
          Protocol::Version3.new
        end

        sig { override.returns(String) }
        def local_header
          'k3.local-wrap.pie.'
        end

        sig { override.returns(String) }
        def secret_header
          'k3.secret-wrap.pie.'
        end

        sig { params(wrapping_key: SymmetricKey).void }
        def initialize(wrapping_key)
          @wrapping_key = wrapping_key
        end

        sig { override.params(nonce: String).returns(String) }
        def authentication_key(nonce:)
          protocol.hmac("#{DOMAIN_SEPARATOR_AUTH}#{nonce}", key: @wrapping_key.to_bytes, digest_size: 32)
        end

        sig { override.params(payload: String, auth_key: String).returns(String) }
        def authentication_tag(payload:, auth_key:)
          protocol.hmac(payload, key: auth_key)
        end

        sig { override.params(data: String).returns({ t: String, n: String, c: String }) }
        def decode_and_split(data)
          b = Util.decode64(data)
          {
            t: T.must(b.byteslice(0, 48)),
            n: T.must(b.byteslice(48, 32)),
            c: T.must(b.byteslice(80..))
          }
        end

        sig { override.returns(String) }
        def random_nonce
          SecureRandom.bytes(32)
        end

        sig { override.params(nonce: String, payload: String).returns(String) }
        def crypt(nonce:, payload:)
          x = OpenSSL::HMAC.digest('SHA384', @wrapping_key.to_bytes, "#{DOMAIN_SEPARATOR_ENCRYPT}#{nonce}")
          ek = T.must(x[0, 32])
          n2 = T.must(x[32..])

          protocol.crypt(key: ek, nonce: n2, payload: payload)
        end
      end
    end
  end
end
