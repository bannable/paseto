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
        @coder = T.let(protocol.id, Interface::ID)
      end

      sig(:final) { params(key: SymmetricKey).returns(String) }
      def lid(key)
        @coder.encode('lid', key.paserk)
      end

      sig(:final) { params(key: AsymmetricKey).returns(String) }
      def sid(key)
        raise ArgumentError, 'no private key available' unless key.private?

        @coder.encode('sid', key.paserk)
      end

      sig(:final) { params(key: AsymmetricKey).returns(String) }
      def pid(key)
        @coder.encode('pid', key.public_paserk)
      end
    end
  end
end
