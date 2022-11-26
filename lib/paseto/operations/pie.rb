# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Operations
    class PIE
      extend T::Sig

      include Interface::Wrapper

      DOMAIN_SEPARATOR_AUTH = "\x81"
      DOMAIN_SEPARATOR_ENCRYPT = "\x80"

      sig { params(wrapping_key: T.all(Key, Interface::Symmetric)).void }
      def initialize(wrapping_key)
        case wrapping_key
        when V3::Version
          coder = PIE::Version3
        when V4::Version
          coder = PIE::Version4
        else
          raise ArgumentError, 'not a valid type of key'
        end
        @wrapping_key = wrapping_key
        @coder = T.let(coder.new(wrapping_key), Interface::PIE)
      end

      sig { override.params(key: Key, nonce: T.nilable(String)).returns(String) }
      def encode(key, nonce: nil)
        raise IncorrectKeyType unless key.version == @wrapping_key.version

        @coder.encode(key, nonce)
      end

      sig { override.params(paserk: [String, String, String, String]).returns(Key) }
      def decode(paserk)
        paserk => [version, type, protocol, data]
        raise UnknownProtocol, 'payload does not use PIE' unless protocol == 'pie'
        raise ParseError, 'not a valid PIE PASERK' if data.empty?
        raise IncorrectKeyType unless version == @wrapping_key.paserk_version

        pie_header = "#{version}.#{type}.pie."
        ptk = @coder.decode(pie_header, data)

        PaserkTypes.deserialize("#{version}.#{type}").generate(ptk)
      end
    end
  end
end
