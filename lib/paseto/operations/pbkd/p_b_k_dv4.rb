# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    module PBKD
      class PBKDv4
        extend T::Sig

        include Interface::PBKD

        sig { override.returns(Protocol::Version4) }
        attr_reader :protocol

        sig { params(password: String).void }
        def initialize(password)
          @password = password
          @protocol = T.let(Protocol::Version4.instance, Protocol::Version4)
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
        def authenticate(header:, pre_key:, salt:, nonce:, edk:, params:) # rubocop:disable Metrics/ParameterLists
          memlimit_int = RbNaCl::PasswordHash::Argon2.memlimit_value(params[:memlimit])
          opslimit_int = RbNaCl::PasswordHash::Argon2.opslimit_value(params[:opslimit])
          memlimit = Util.int_to_be64(memlimit_int)
          opslimit = Util.int_to_be32(opslimit_int)
          para = Util.int_to_be32(1)

          message = "#{salt}#{memlimit}#{opslimit}#{para}#{nonce}#{edk}"

          ak = protocol.digest("#{Operations::PBKW::DOMAIN_SEPARATOR_AUTH}#{pre_key}", digest_size: 32)
          tag = protocol.hmac("#{header}.#{message}", key: ak, digest_size: 32)

          [message, tag]
        end

        sig { override.params(salt: String, params: T::Hash[Symbol, Integer]).returns(String) }
        def pre_key(salt:, params:)
          opslimit = T.must(params[:opslimit])
          memlimit = T.must(params[:memlimit])
          protocol.kdf(@password, salt:, length: 32, opslimit:, memlimit:)
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
        def decode(payload) # rubocop:disable Metrics/AbcSize
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
