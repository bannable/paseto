# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PIE
      class Version4
        extend T::Sig

        include Interface::PIE

        DOMAIN_SEPARATOR_AUTH = "\x81"
        DOMAIN_SEPARATOR_ENCRYPT = "\x80"

        sig { params(wrapping_key: T.all(Key, Interface::Symmetric)).void }
        def initialize(wrapping_key)
          @wrapping_key = wrapping_key
        end

        sig { override.params(nonce: String).returns(String) }
        def authentication_key(nonce:)
          RbNaCl::Hash.blake2b(DOMAIN_SEPARATOR_AUTH + nonce, key: @wrapping_key.to_bytes, digest_size: 32)
        end

        sig { override.params(payload: String, auth_key: String).returns(String) }
        def authentication_tag(payload:, auth_key:)
          RbNaCl::Hash.blake2b(payload, key: auth_key, digest_size: 32)
        end

        sig { override.returns(String) }
        def random_nonce
          RbNaCl::Random.random_bytes(32)
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

        sig { override.params(nonce: String, payload: String).returns(String) }
        def crypt(nonce:, payload:)
          x = RbNaCl::Hash.blake2b(DOMAIN_SEPARATOR_ENCRYPT + nonce, key: @wrapping_key.to_bytes, digest_size: 56)
          ek = T.must(x[0, 32])
          n2 = T.must(x[32..])

          Paseto::Sodium::Stream::XChaCha20Xor.new(ek).encrypt(n2, payload)
        end
      end
    end
  end
end