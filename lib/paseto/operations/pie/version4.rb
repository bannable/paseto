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

        sig { override.params(header: String, data: String).returns(String) }
        def decode(header, data)
          # :nocov:
          decode_and_split(data) => {t:, n:, c:}
          # :nocov:

          ak = RbNaCl::Hash.blake2b(DOMAIN_SEPARATOR_AUTH + n, key: @wrapping_key.to_bytes, digest_size: 32)
          t2 = RbNaCl::Hash.blake2b((header + n + c), key: ak, digest_size: 32)

          raise InvalidAuthenticator unless Util.constant_compare(t, t2)

          crypt(nonce: n, payload: c)
        end

        sig { override.params(key: T.all(Paseto::Key, Paseto::V4::Version), nonce: T.nilable(String)).returns(String) }
        def encode(key, nonce)
          nonce ||= RbNaCl::Random.random_bytes(32)

          h = pie_header(key)
          c = crypt(nonce: nonce, payload: key.to_bytes)

          ak = RbNaCl::Hash.blake2b(DOMAIN_SEPARATOR_AUTH + nonce, key: @wrapping_key.to_bytes, digest_size: 32)
          t = RbNaCl::Hash.blake2b((h + nonce + c), key: ak, digest_size: 32)

          h + Util.encode64(t + nonce + c)
        end

        private

        sig { params(key: Key).returns(String) }
        def pie_header(key)
          case key
          when Interface::Symmetric then 'k4.local-wrap.pie.'
          when Interface::Asymmetric then 'k4.secret-wrap.pie.'
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
            t: T.must(b.byteslice(0, 32)),
            n: T.must(b.byteslice(32, 32)),
            c: T.must(b.byteslice(64..))
          }
        end

        sig { params(nonce: String, payload: String).returns(String) }
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
