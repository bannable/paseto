# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PBKW
      DOMAIN_SEPARATOR_ENCRYPT = T.let("\xFF", String)
      DOMAIN_SEPARATOR_AUTH = T.let("\xFE", String)

      extend T::Sig

      sig { params(key: Interface::Key, password: String, options: T::Hash[Symbol, T.any(Integer, Symbol)]).returns(String) }
      def self.pbkw(key, password, options = {})
        new(key.protocol, password).encode(key, options)
      end

      sig { params(version: Interface::Version, password: String).void }
      def initialize(version, password)
        @coder = T.let(version.pbkw(password), Interface::PBKD)
      end

      sig { params(key: Interface::Key, options: T::Hash[Symbol, T.any(Integer, Symbol)]).returns(String) }
      def encode(key, options)
        raise LucidityError unless key.protocol == @coder.protocol

        opts = default_options.merge(options)

        h = key.pbkw_header
        salt = @coder.random_salt
        nonce = @coder.random_nonce

        pre_key = @coder.pre_key(salt:, params: opts)

        edk = @coder.crypt(payload: key.to_bytes, key: pre_key, nonce:)

        message, t = @coder.authenticate(header: h, pre_key:, salt:, nonce:, edk:, params: opts)

        data = Util.encode64("#{message}#{t}")
        "#{h}.#{data}"
      end

      sig { params(paserk: String).returns(Interface::Key) }
      def decode(paserk)
        paserk.split('.') => [version, type, data]
        raise LucidityError unless version == @coder.paserk_version

        header = "#{version}.#{type}"

        @coder.decode(data) => {salt:, nonce:, edk:, tag:, params:}

        pre_key = @coder.pre_key(salt:, params:)

        _, t2 = @coder.authenticate(header:, pre_key:, salt:, nonce:, edk:, params:)
        raise InvalidAuthenticator unless Util.constant_compare(t2, tag)

        ptk = @coder.crypt(payload: edk, key: pre_key, nonce:)
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
