# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    module PBKD
      class PBKDv3
        extend T::Sig

        DOMAIN_SEPARATOR_ENCRYPT = T.let("\xFF", String)
        DOMAIN_SEPARATOR_AUTH = T.let("\xFE", String)

        include Interface::PBKD

        sig { override.returns(Protocol::Version3) }
        def self.protocol
          Protocol::Version3.new
        end

        sig { params(password: String).void }
        def initialize(password)
          @password = password
        end

        sig { override.params(key: Interface::Key, options: T::Hash[Symbol, Integer]).returns(String) }
        def wrap(key, options)
          options => {iterations:}

          h = key.pbkw_header
          salt = SecureRandom.random_bytes(32)
          nonce = SecureRandom.random_bytes(16)

          pre_key = protocol.kdf(@password, salt: salt, length: 32, iterations: iterations)

          edk = crypt(payload: key.to_bytes, nonce: nonce, pre_key: pre_key)

          message = "#{salt}#{Util.int_to_be32(iterations)}#{nonce}#{edk}"
          t = authenticate(pre_key: pre_key, message: "#{h}#{message}")

          [h, Util.encode64("#{message}#{t}")].join
        end

        sig { override.params(header: String, data: String).returns(Interface::Key) }
        def unwrap(header, data)
          h = "#{header}."
          decode(data) => {salt:, iterations:, nonce:, edk:, authentication_tag:}

          pre_key = OpenSSL::KDF.pbkdf2_hmac(@password, salt: salt, iterations: Util.be32_to_int(iterations), length: 32, hash: 'SHA384')

          message = "#{h}#{salt}#{iterations}#{nonce}#{edk}"
          t2 = authenticate(pre_key: pre_key, message: message)

          raise InvalidAuthenticator unless Util.constant_compare(t2, authentication_tag)

          ptk = crypt(payload: edk, nonce: nonce, pre_key: pre_key)

          PaserkTypes.deserialize(header).generate(ptk)
        end

        private

        sig { params(pre_key: String, message: String).returns(String) }
        def authenticate(pre_key:, message:)
          ak = protocol.digest("#{DOMAIN_SEPARATOR_AUTH}#{pre_key}")
          protocol.hmac(message, key: ak)
        end

        sig { params(payload: String, pre_key: String, nonce: String).returns(String) }
        def crypt(payload:, pre_key:, nonce:)
          ek = protocol.digest("#{DOMAIN_SEPARATOR_ENCRYPT}#{pre_key}", digest_size: 32)

          protocol.crypt(key: ek, nonce: nonce, payload: payload)
        end

        sig do
          params(
            payload: String
          ).returns(
            {
              salt: String,
              iterations: String,
              nonce: String,
              edk: String,
              authentication_tag: String
            }
          )
        end
        def decode(payload)
          data = Util.decode64(payload)
          edk_len = data.bytesize - 100
          {
            salt: T.must(data.byteslice(0, 32)),
            iterations: T.must(data.byteslice(32, 4)),
            nonce: T.must(data.byteslice(36, 16)),
            edk: T.must(data.byteslice(52, edk_len)),
            authentication_tag: T.must(data.byteslice(-48, 48))
          }
        end
      end
    end
  end
end
