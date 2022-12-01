# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class Wrap
      extend T::Sig

      DOMAIN_SEPARATOR_AUTH = "\x81"
      DOMAIN_SEPARATOR_ENCRYPT = "\x80"

      sig { params( wrapping_key: SymmetricKey, paserk: [String, String, String, String]).returns(Interface::Key) }
      def self.unwrap(wrapping_key, paserk)
        case paserk
        in [_, _, _, data] if data.empty?
          raise ParseError, 'empty paserk payload'
        in [_, _, String => protocol, _] if protocol == 'pie'
          PIE.new(wrapping_key).decode(paserk)
        else
          raise UnknownProtocol, protocol
        end
      end

      sig { params(key: Interface::Key, wrapping_key: SymmetricKey, nonce: T.nilable(String)).returns(String) }
      def self.wrap(key, wrapping_key:, nonce: nil)
        PIE.new(wrapping_key).encode(key, nonce: nonce)
      end
    end
  end
end
