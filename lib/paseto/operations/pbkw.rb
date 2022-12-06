# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PBKW
      extend T::Sig

      sig { params(key: Interface::Key, password: String, options: T::Hash[Symbol, T.any(Integer, Symbol)]).returns(String) }
      def self.pbkw(key, password, options = {})
        new(key.protocol, password).encode(key, options)
      end

      sig { params(version: Interface::Version, password: String).void }
      def initialize(version, password)
        case version
        in Protocol::Version3
          coder = PBKD::PBKDv3
        in Protocol::Version4 if Paseto.rbnacl?
          coder = PBKD::PBKDv4
        else
          raise UnknownProtocol
        end
        @coder = T.let(coder.new(password), Interface::PBKD)
      end

      sig { params(key: Interface::Key, options: T::Hash[Symbol, T.any(Integer, Symbol)]).returns(String) }
      def encode(key, options)
        raise LucidityError unless key.protocol == @coder.protocol

        opts = default_options.merge(options)

        h = key.pbkw_header
        salt = @coder.random_salt
        nonce = @coder.random_nonce

        pre_key = @coder.pre_key(salt: salt, params: opts)

        edk = @coder.crypt(payload: key.to_bytes, key: pre_key, nonce: nonce)

        message, t = @coder.authenticate(header: h, pre_key: pre_key, salt: salt, nonce: nonce, edk: edk, params: opts)

        data = Util.encode64("#{message}#{t}")
        "#{h}#{data}"
      end

      sig { params(paserk: String).returns(Interface::Key) }
      def decode(paserk)
        paserk.split('.') => [version, type, data]
        raise LucidityError unless version == @coder.paserk_version

        header = "#{version}.#{type}"

        @coder.decode(data) => {salt:, nonce:, edk:, tag:, params:}

        pre_key = @coder.pre_key(salt: salt, params: params)

        _, t2 = @coder.authenticate(header: header, pre_key: pre_key, salt: salt, nonce: nonce, edk: edk, params: params)
        raise InvalidAuthenticator unless Util.constant_compare(t2, tag)

        ptk = @coder.crypt(payload: edk, key: pre_key, nonce: nonce)
        PaserkTypes.deserialize(header).generate(ptk)
      end

      private

      sig { returns({ iterations: Integer, memlimit: Symbol, opslimit: Symbol }) }
      def default_options
        {
          iterations: 100_000,
          memlimit: :interactive,
          opslimit: :interactive
        }
      end
    end
  end
end
