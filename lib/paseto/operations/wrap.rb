# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class Wrap
      extend T::Sig

      DOMAIN_SEPARATOR_AUTH = "\x81"
      DOMAIN_SEPARATOR_ENCRYPT = "\x80"

      sig do
        params(
          wrapping_key: T.all(Key, Interface::Symmetric),
          paserk: [String, String, String, String]
        ).returns(Key)
      end
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

      sig do
        params(
          key: Key,
          wrapping_key: T.all(Key, Interface::Symmetric),
          nonce: T.nilable(String)
        ).returns(String)
      end
      def self.wrap(key, wrapping_key:, nonce: nil)
        PIE.new(wrapping_key).encode(key, nonce: nonce)
      end
    end
  end
end
