# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PBKW
      extend T::Sig

      sig { params(version: Interface::Version, password: String).void }
      def initialize(version, password)
        @version = version
        case @version
        in Protocol::Version3
          coder = PBKD::PBKDv3
        in Protocol::Version4 if Paseto.rbnacl?
          coder = PBKD::PBKDv4
        else
          raise UnknownProtocol
        end
        @coder = T.let(coder.new(password), Interface::PBKD)
      end

      sig { params(key: Key, options: T::Hash[Symbol, T.any(Integer, Symbol)]).returns(String) }
      def encode(key, options)
        raise LucidityError unless key.version == @coder.version

        opts = default_options.merge(options)
        @coder.wrap(key, **opts)
      end

      sig { params(paserk: String).returns(Key) }
      def decode(paserk)
        paserk.split('.') => [version, type, data]
        raise LucidityError unless version == @coder.paserk_version

        header = "#{version}.#{type}"
        @coder.unwrap(header, data)
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
