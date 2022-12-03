# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class ID
      extend T::Sig

      sig(:final) { params(key: SymmetricKey).returns(String) }
      def self.lid(key)
        new(key.protocol).lid(key)
      end

      sig(:final) { params(key: AsymmetricKey).returns(String) }
      def self.sid(key)
        new(key.protocol).sid(key)
      end

      sig(:final) { params(key: AsymmetricKey).returns(String) }
      def self.pid(key)
        new(key.protocol).pid(key)
      end

      sig { params(protocol: Interface::Version).void }
      def initialize(protocol)
        case protocol
        in Protocol::Version3
          coder = ID::IDv3.new
        in Protocol::Version4 if Paseto.rbnacl?
          coder = ID::IDv4.new
        else
          raise UnknownProtocol
        end
        @coder = T.let(coder, Interface::ID)
      end

      sig(:final) { params(key: SymmetricKey).returns(String) }
      def lid(key)
        @coder.encode('lid', key.to_paserk)
      end

      sig(:final) { params(key: AsymmetricKey).returns(String) }
      def sid(key)
        raise ArgumentError, 'no private key available' unless key.private?

        @coder.encode('sid', key.to_paserk)
      end

      sig(:final) { params(key: AsymmetricKey).returns(String) }
      def pid(key)
        @coder.encode('pid', key.to_paserk(pub: true))
      end
    end
  end
end
