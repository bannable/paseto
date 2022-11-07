# encoding: binary
# frozen_string_literal: true

module Paseto
  module V4
    class Public < Key
      SIGNATURE_BYTES = 64

      def self.generate
        new(private_key: RbNaCl::SigningKey.generate.to_s)
      end

      def initialize(private_key: "", public_key: "")
        if private_key.bytesize.positive?
          raise ArgumentError, "may not provide both private and public keys" unless public_key.empty?

          @private_key = RbNaCl::SigningKey.new(private_key)
          @public_key = @private_key.verify_key
        elsif public_key.bytesize.positive?
          @public_key = RbNaCl::VerifyKey.new(public_key)
        else
          raise ArgumentError, "must provide one of private or public key"
        end

        super(version: "v4", purpose: "public")
      rescue RbNaCl::LengthError
        raise CryptoError, "incorrect key size"
      end

      def sign(message:, footer: "", implicit_assertion: "")
        raise ArgumentError, "no private key available" unless private_key

        m = message.to_s
        m2 = Util.pre_auth_encode("v4.public.", m, footer, implicit_assertion)
        sig = private_key.sign(m2)
        payload = m + sig
        Token.new(payload: payload, purpose: purpose, version: version, footer: footer)
      end

      def verify(token:, implicit_assertion: "")
        # OPTIONAL: verify footer is expected, constant-time
        raise ParseError, "incorrect header for key type v4.public" unless header == token.header

        m = token.payload
        raise ParseError, "message too short" if m.size < SIGNATURE_BYTES

        s = m.slice!(-SIGNATURE_BYTES, SIGNATURE_BYTES) || ""
        m2 = Util.pre_auth_encode("v4.public.", m, token.footer, implicit_assertion)

        begin
          public_key.verify(s, m2)
        rescue RbNaCl::BadSignatureError
          raise InvalidSignature
        end

        m
      end

      def public_key
        @public_key
      end

      private

      def private_key
        @private_key
      end
    end
  end
end
