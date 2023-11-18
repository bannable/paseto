# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Wrappers
    class PIE
      class PieV4
        extend T::Sig

        include Interface::PIE

        DOMAIN_SEPARATOR_AUTH = "\x81"
        DOMAIN_SEPARATOR_ENCRYPT = "\x80"

        sig { override.returns(Protocol::Version4) }
        attr_reader :protocol

        sig { override.returns(String) }
        attr_reader :local_header

        sig { override.returns(String) }
        attr_reader :secret_header

        sig { params(wrapping_key: SymmetricKey).void }
        def initialize(wrapping_key)
          @local_header = T.let('k4.local-wrap.pie.', String)
          @protocol = T.let(Protocol::Version4.instance, Protocol::Version4)
          @secret_header = T.let('k4.secret-wrap.pie.', String)
          @wrapping_key = wrapping_key
        end

        sig { override.params(nonce: String).returns(String) }
        def authentication_key(nonce:)
          protocol.hmac("#{DOMAIN_SEPARATOR_AUTH}#{nonce}", key: @wrapping_key.to_bytes, digest_size: 32)
        end

        sig { override.params(payload: String, auth_key: String).returns(String) }
        def authentication_tag(payload:, auth_key:)
          protocol.hmac(payload, key: auth_key, digest_size: 32)
        end

        sig { override.params(data: String).returns({ t: String, n: String, c: String }) }
        def decode_and_split(data)
          b = Util.decode64(data)
          {
            t: T.must(b.byteslice(0, 32)),
            n: T.must(b.byteslice(32, 32)),
            c: T.must(b.byteslice(64..))
          }
        end

        sig { override.returns(String) }
        def random_nonce
          protocol.random(32)
        end

        sig { override.params(nonce: String, payload: String).returns(String) }
        def crypt(nonce:, payload:)
          x = protocol.hmac("#{DOMAIN_SEPARATOR_ENCRYPT}#{nonce}", key: @wrapping_key.to_bytes, digest_size: 56)
          ek = T.must(x[0, 32])
          n2 = T.must(x[32..])

          protocol.crypt(key: ek, nonce: n2, payload:)
        end
      end
    end
  end
end
