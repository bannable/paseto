# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Wrappers
    class PIE
      extend T::Sig

      include Interface::Wrapper

      sig { params(wrapping_key: SymmetricKey).void }
      def initialize(wrapping_key)
        @wrapping_key = wrapping_key
        @coder = T.let(wrapping_key.protocol.pie(@wrapping_key), Interface::PIE)
      end

      sig { override.params(key: Interface::Key, nonce: T.nilable(String)).returns(String) }
      def encode(key, nonce: nil)
        raise LucidityError unless key.version == @wrapping_key.version

        nonce ||= @coder.random_nonce
        header = pie_header(key)

        c = @coder.crypt(nonce: nonce, payload: key.to_bytes)

        ak = @coder.authentication_key(nonce: nonce)
        t = @coder.authentication_tag(payload: "#{header}#{nonce}#{c}", auth_key: ak)

        [header, Util.encode64("#{t}#{nonce}#{c}")].join
      end

      sig { override.params(paserk: [String, String, String, String]).returns(Interface::Key) }
      def decode(paserk)
        paserk => [version, type, protocol, data]
        raise UnknownProtocol, 'payload does not use PIE' unless protocol == 'pie'
        raise ParseError, 'not a valid PIE PASERK' if data.empty?
        raise LucidityError unless version == @wrapping_key.paserk_version

        header = "#{version}.#{type}.pie."

        # :nocov:
        @coder.decode_and_split(data) => {t:, n:, c:}
        # :nocov:

        ak = @coder.authentication_key(nonce: n)
        t2 = @coder.authentication_tag(payload: "#{header}#{n}#{c}", auth_key: ak)

        raise InvalidAuthenticator unless Util.constant_compare(t, t2)

        ptk = @coder.crypt(nonce: n, payload: c)

        PaserkTypes.deserialize("#{version}.#{type}").generate(ptk)
      end

      private

      sig { params(key: Interface::Key).returns(String) }
      def pie_header(key)
        case key
        when SymmetricKey then @coder.local_header
        when AsymmetricKey then @coder.secret_header
        else
          # :nocov:
          raise ArgumentError, 'not a valid type of key'
          # :nocov:
        end
      end
    end
  end
end
