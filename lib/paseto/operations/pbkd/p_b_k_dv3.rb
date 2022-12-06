# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    module PBKD
      class PBKDv3
        extend T::Sig

        include Interface::PBKD

        sig { override.returns(Protocol::Version3) }
        def self.protocol
          Protocol::Version3.new
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
        def authenticate(header:, pre_key:, salt:, nonce:, edk:, params:) # rubocop:disable Metrics/ParameterLists
          iterations = Util.int_to_be32(T.must(params[:iterations]))

          message = "#{salt}#{iterations}#{nonce}#{edk}"

          ak = protocol.digest("#{Operations::PBKW::DOMAIN_SEPARATOR_AUTH}#{pre_key}")
          tag = protocol.hmac("#{header}.#{message}", key: ak)
          [message, tag]
        end

        sig { override.params(salt: String, params: T::Hash[Symbol, Integer]).returns(String) }
        def pre_key(salt:, params:)
          iterations = T.must(params[:iterations])
          protocol.kdf(@password, salt: salt, length: 32, iterations: iterations)
        end

        sig { override.returns(String) }
        def random_nonce
          protocol.random(16)
        end

        sig { override.returns(String) }
        def random_salt
          protocol.random(32)
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
          edk_len = data.bytesize - 100
          iterations = Util.be32_to_int(T.must(data.byteslice(32, 4)))
          {
            salt: T.must(data.byteslice(0, 32)),
            nonce: T.must(data.byteslice(36, 16)),
            edk: T.must(data.byteslice(52, edk_len)),
            tag: T.must(data.byteslice(-48, 48)),
            params: { iterations: iterations }
          }
        end
      end
    end
  end
end
