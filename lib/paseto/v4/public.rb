# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module V4
    # PASETOv4 `public` token interface providing asymmetric signature signing and verification of tokens.
    class Public < Paseto::Key
      # Number of bytes in an Ed25519 signature
      SIGNATURE_BYTES = 64

      # Ed25519 private key object
      sig { returns(T.nilable(RbNaCl::Signatures::Ed25519::SigningKey)) }
      attr_reader :private_key

      # Ed25519 public key object
      sig { returns(RbNaCl::Signatures::Ed25519::VerifyKey) }
      attr_reader :public_key

      # Create a new Public instance with a brand new Ed25519 key.
      sig { returns(Public) }
      def self.generate
        new(private_key: RbNaCl::SigningKey.generate.to_s)
      end

      # Either `private_key` or `public_key` must be a 32 byte string, which is used as a
      # seed for Ed25519 key generation. Only one of `private_key` or `public_key` is allowed.
      sig { params(private_key: T.nilable(String), public_key: T.nilable(String)).void }
      def initialize(private_key: nil, public_key: nil)
        if private_key
          raise ArgumentError, 'may not provide both private and public keys' if public_key

          @private_key = T.let(RbNaCl::SigningKey.new(private_key), RbNaCl::SigningKey)
          @public_key = T.let(@private_key.verify_key, RbNaCl::VerifyKey)
        elsif public_key
          @public_key = T.let(RbNaCl::VerifyKey.new(public_key), RbNaCl::VerifyKey)
        else
          raise ArgumentError, 'must provide one of private or public key'
        end

        super(version: 'v4', purpose: 'public')
      rescue RbNaCl::LengthError
        raise CryptoError, 'incorrect key size'
      end

      # Sign `message` and optional non-empty `footer` and return a Token.
      # The resulting token may be bound to a particular use by passing a non-empty `implicit_assertion`.
      sig { params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: '')
        raise ArgumentError, 'no private key available' unless private_key

        m = message.to_s
        m2 = Util.pre_auth_encode(pae_header, m, footer, implicit_assertion)
        sig = T.must(private_key).sign(m2)
        payload = m + sig
        Token.new(payload:, purpose:, version:, footer:)
      end

      # Verify the signature of `token`, with an optional binding `implicit_assertion`. `token` must be a `v4.public`` type Token.
      # Returns the verified payload if successful, otherwise raises an exception.
      sig { params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: '')
        # OPTIONAL: verify footer is expected, constant-time
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        m = token.payload
        raise ParseError, 'message too short' if m.size < SIGNATURE_BYTES

        s = m.slice!(-SIGNATURE_BYTES, SIGNATURE_BYTES) || ''
        m2 = Util.pre_auth_encode(pae_header, m, token.footer, implicit_assertion)

        begin
          public_key.verify(s, m2)
        rescue RbNaCl::BadSignatureError
          raise InvalidSignature
        end

        m
      end
    end
  end
end
