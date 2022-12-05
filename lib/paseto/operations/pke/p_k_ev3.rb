# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PKE
      class PKEv3
        extend T::Sig

        include Interface::PKE

        sig { override.params(message: String, ek: String, n: String).returns(String) }
        def self.crypt(message:, ek:, n:)
          cipher = OpenSSL::Cipher.new('aes-256-ctr')
          cipher.key = ek
          cipher.iv = n
          cipher.update(message) + cipher.final
        end

        sig(:final) { override.returns(OpenSSL::PKey::EC) }
        def self.generate_ephemeral_key
          OpenSSL::PKey::EC.generate('secp384r1')
        end

        sig(:final) { override.returns(String) }
        def self.header
          'k3.seal.'
        end

        sig { override.params(esk: OpenSSL::PKey::EC).returns(String) }
        def self.epk_bytes_from_esk(esk)
          esk.public_key.to_octet_string(:compressed)
        end

        sig { override.params(encoded_data: String).returns([String, OpenSSL::PKey::EC::Point, String]) }
        def self.split(encoded_data)
          data = Util.decode64(encoded_data)

          t = T.must(data.slice(0, 48))

          epk_bytes = T.must(data.slice(48, 49))
          epk = OpenSSL::PKey::EC::Point.new(OpenSSL::PKey::EC::Group.new('secp384r1'), epk_bytes)

          edk = T.must(data.slice(97, 32))

          [t, epk, edk]
        end

        sig { params(sealing_key: AsymmetricKey).void }
        def initialize(sealing_key)
          case sealing_key
          when V3::Public then nil
          else raise LucidityError
          end

          @sealing_key = T.let(sealing_key, V3::Public)
          @pk = T.let(@sealing_key.public_bytes, String)
        end

        sig { override.params(xk: String, epk: OpenSSL::PKey::EC::Point).returns({ ek: String, n: String }) }
        def derive_ek_n(xk:, epk:)
          epk_bytes = epk.to_octet_string(:compressed)

          x = OpenSSL::Digest.digest(
            'SHA384',
            "#{DOMAIN_SEPARATOR_ENCRYPT}#{header}#{xk}#{epk_bytes}#{@pk}"
          )

          ek = T.must(x[0, 32])
          n = T.must(x[32, 16])

          { ek: ek, n: n }
        end

        sig { override.params(xk: String, epk: OpenSSL::PKey::EC::Point).returns(String) }
        def derive_ak(xk:, epk:)
          epk_bytes = epk.to_octet_string(:compressed)
          OpenSSL::Digest.digest(
            'SHA384',
            "#{DOMAIN_SEPARATOR_AUTH}#{header}#{xk}#{epk_bytes}#{@pk}"
          )
        end

        sig { override.params(ak: String, epk: OpenSSL::PKey::EC::Point, edk: String).returns(String) }
        def tag(ak:, epk:, edk:)
          epk_bytes = epk.to_octet_string(:compressed)
          OpenSSL::HMAC.digest('SHA384', ak, "#{header}#{epk_bytes}#{edk}")
        end

        sig { override.params(message: String, ek: String, n: String).returns(SymmetricKey) }
        def decrypt(message:, ek:, n:)
          pdk = crypt(message: message, ek: ek, n: n)
          V3::Local.new(ikm: pdk)
        end

        private

        sig { override.returns(Paseto::V3::Public) }
        attr_reader :sealing_key
      end
    end
  end
end
