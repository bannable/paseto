# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    module PBKD
      class PBKDv4
        extend T::Sig

        DOMAIN_SEPARATOR_ENCRYPT = T.let("\xFF".b, String)
        DOMAIN_SEPARATOR_AUTH = T.let("\xFE".b, String)

        include Interface::PBKD

        sig { override.returns(Protocol::Version4) }
        def self.protocol
          Protocol::Version4.new
        end

        sig { params(password: String).void }
        def initialize(password)
          @password = password
        end

        sig do
          override.params(
            header: String,
            pre_key: String,
            salt: String,
            nonce: String,
            edk: String,
            params: T::Hash[Symbol, Integer]
          ).returns([String, String])
        end
        def authenticate(header:, pre_key:, salt:, nonce:, edk:, params:)
          memlimit = Util.int_to_be64(T.must(params[:memlimit]))
          opslimit = Util.int_to_be32(T.must(params[:opslimit]))
          para = Util.int_to_be32(1)

          message = "#{salt}#{memlimit}#{opslimit}#{para}#{nonce}#{edk}"

          ak = protocol.digest("#{DOMAIN_SEPARATOR_AUTH}#{pre_key}", digest_size: 32)
          tag = protocol.hmac("#{header}.#{message}", key: ak, digest_size: 32)

          [message, tag]
        end

        sig { override.params(payload: String, key: String, nonce: String).returns(String) }
        def crypt(payload:, key:, nonce:)
          ek = protocol.digest("#{DOMAIN_SEPARATOR_ENCRYPT}#{key}", digest_size: 32)

          protocol.crypt(key: ek, nonce: nonce, payload: payload)
        end

        sig { override.params(salt: String, params: T::Hash[Symbol, Integer]).returns(String) }
        def pre_key(salt:, params:)
          opslimit = T.must(params[:opslimit])
          memlimit = T.must(params[:memlimit])
          protocol.kdf(@password, salt: salt, length: 32, opslimit: opslimit, memlimit: memlimit)
        end

        sig { override.returns(String) }
        def random_nonce
          protocol.random(24)
        end

        sig { override.returns(String) }
        def random_salt
          protocol.random(16)
        end

        sig do
          override.params(payload: String).returns(
            {
              salt: String,
              nonce: String,
              edk: String,
              tag: String,
              params: T::Hash[Symbol, Integer]
            }
          )
        end
        def decode(payload)
          data = Util.decode64(payload)
          edk_len = data.bytesize - 88
          {
            salt: T.must(data.byteslice(0, 16)),
            nonce: T.must(data.byteslice(32, 24)),
            edk: T.must(data.byteslice(56, edk_len)),
            tag: T.must(data.byteslice(-32, 32)),
            params: {
              memlimit: Util.be64_to_int(T.must(data.byteslice(16, 8))),
              opslimit: Util.be32_to_int(T.must(data.byteslice(24, 4))),
              para: Util.be32_to_int(T.must(data.byteslice(28, 4)))
            }
          }
        end
      end
    end
  end
end
