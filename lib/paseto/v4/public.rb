# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module V4
    # PASETOv4 `public` token interface providing asymmetric signature signing and verification of tokens.
    class Public < Paseto::Key
      include Interface::Asymmetric

      final!

      # Number of bytes in an Ed25519 signature
      SIGNATURE_BYTES = 64

      # Ed25519 key object
      sig(:final) { returns(OpenSSL::PKey::PKey) }
      attr_reader :key

      # Create a new Public instance with a brand new Ed25519 key.
      sig(:final) { returns(Public) }
      def self.generate
        new(OpenSSL::PKey.generate_key('ED25519').private_to_der)
      end

      # `private_key` and `public_key` are DER- or PEM-encoded. For `private_key`, the value must
      # be an encoded scalar. For `public_key`, the value must be an encoded group element.
      sig(:final) { params(key_material: String).void }
      def initialize(key_material)
        @key = T.let(OpenSSL::PKey.read(key_material), OpenSSL::PKey::PKey)
        raise CryptoError, "expected Ed25519 key, got #{key.oid}" unless key.oid == 'ED25519'

        super(version: 'v4', purpose: 'public')
      end

      # Sign `message` and optional non-empty `footer` and return a Token.
      # The resulting token may be bound to a particular use by passing a non-empty `implicit_assertion`.
      sig(:final) { override.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: '')
        # BUG: https://github.com/openssl/openssl/issues/19524
        #   openssl 1.1.1, openssl 3.0.0 - 3.0.7: missing check for private key during EDDSA signing
        #   workaround by trying to decode the private key and catching any error
        raise ArgumentError, 'no private key available' unless safe_for_signing?

        m = message
        m2 = Util.pre_auth_encode(pae_header, m, footer, implicit_assertion)
        sig = key.sign(nil, m2)
        payload = m + sig
        Token.new(payload:, purpose:, version:, footer:)
      end

      # Verify the signature of `token`, with an optional binding `implicit_assertion`. `token` must be a `v4.public`` type Token.
      # Returns the verified payload if successful, otherwise raises an exception.
      sig(:final) { override.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: '')
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        m = token.payload
        raise ParseError, 'message too short' if m.size < SIGNATURE_BYTES

        s = T.must(m.slice!(-SIGNATURE_BYTES, SIGNATURE_BYTES))
        m2 = Util.pre_auth_encode(pae_header, m, token.footer, implicit_assertion)

        raise InvalidSignature unless key.verify(nil, s, m2)

        m.encode!(Encoding::UTF_8)
      rescue Encoding::UndefinedConversionError
        raise ParseError, 'invalid payload encoding'
      end

      private

      sig(:final) { returns(T::Boolean) }
      def safe_for_signing?
        key_text = key.to_text
        return false if !Util.openssl?(3, 0, 8) && Util.openssl?(3) && key_text.start_with?('ED25519 Public-Key')
        return false if Util.openssl?(1, 1, 1) && key_text == "<INVALID PRIVATE KEY>\n"

        true
      end
    end
  end
end
