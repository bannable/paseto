# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PKE
      class PKEv4
        extend T::Sig

        include Interface::PKE

        sig { override.params(esk: RbNaCl::PrivateKey).returns(String) }
        def self.epk_bytes_from_esk(esk)
          esk.public_key.to_bytes
        end

        sig(:final) { override.returns(RbNaCl::PrivateKey) }
        def self.generate_ephemeral_key
          RbNaCl::PrivateKey.generate
        end

        sig(:final) { override.returns(String) }
        def self.header
          'k4.seal.'
        end

        sig { override.returns(Protocol::Version4) }
        def self.protocol
          Protocol::Version4.new
        end

        sig { override.params(encoded_data: String).returns([String, RbNaCl::PublicKey, String]) }
        def self.split(encoded_data)
          data = Util.decode64(encoded_data)

          t = T.must(data.slice(0, 32))

          epk_bytes = T.must(data.slice(32, 32))
          epk = RbNaCl::PublicKey.new(epk_bytes)

          edk = T.must(data.slice(64, 32))

          [t, epk, edk]
        end

        sig { params(sealing_key: AsymmetricKey).void }
        def initialize(sealing_key)
          case sealing_key
          when V4::Public then nil
          else raise LucidityError
          end

          @sealing_key = T.let(sealing_key, V4::Public)
          @pk = T.let(@sealing_key.x25519_public_key, RbNaCl::PublicKey)
          @pk_bytes = T.let(@pk.to_bytes, String)
        end

        sig { override.params(message: String, ek: String, n: String).returns(SymmetricKey) }
        def decrypt(message:, ek:, n:)
          pdk = protocol.crypt(payload: message, key: ek, nonce: n)
          V4::Local.new(ikm: pdk)
        end

        sig { override.params(xk: String, epk: RbNaCl::PublicKey).returns({ ek: String, n: String }) }
        def derive_ek_n(xk:, epk:)
          ek = protocol.digest(
            "#{DOMAIN_SEPARATOR_ENCRYPT}#{header}#{xk}#{epk.to_bytes}#{@pk_bytes}",
            digest_size: 32
          )
          n = protocol.digest("#{epk.to_bytes}#{@pk_bytes}", digest_size: 24)

          { ek: ek, n: n }
        end

        sig { override.params(xk: String, epk: RbNaCl::PublicKey).returns(String) }
        def derive_ak(xk:, epk:)
          protocol.digest([DOMAIN_SEPARATOR_AUTH, header, xk, epk.to_bytes, @pk_bytes].join, digest_size: 32)
        end

        sig { override.params(message: String, ek: String, n: String).returns(String) }
        def encrypt(message:, ek:, n:)
          protocol.crypt(payload: message, key: ek, nonce: n)
        end

        sig { override.params(ak: String, epk: RbNaCl::PublicKey, edk: String).returns(String) }
        def tag(ak:, epk:, edk:)
          protocol.hmac("#{header}#{epk.to_bytes}#{edk}", key: ak, digest_size: 32)
        end

        private

        sig { override.returns(Paseto::V4::Public) }
        attr_reader :sealing_key
      end
    end
  end
end
