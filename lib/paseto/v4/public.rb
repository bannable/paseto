# typed: strict
# encoding: binary
# frozen_string_literal: true

module Paseto
  module V4
    class Public < Paseto::Key
      # Number of bytes in an Ed25519 signature
      SIGNATURE_BYTES = 64

      sig { returns(T.nilable(RbNaCl::Signatures::Ed25519::SigningKey)) }
      attr_reader :private_key

      sig { returns(RbNaCl::Signatures::Ed25519::VerifyKey) }
      attr_reader :public_key

      sig { returns(Public) }
      def self.generate
        new(private_key: RbNaCl::SigningKey.generate.to_s)
      end

      sig { params(private_key: String, public_key: String).void }
      def initialize(private_key: "", public_key: "")
        if private_key.bytesize.positive?
          raise ArgumentError, "may not provide both private and public keys" unless public_key.empty?

          @private_key = T.let(RbNaCl::SigningKey.new(private_key), RbNaCl::SigningKey)
          @public_key = T.let(@private_key.verify_key, RbNaCl::VerifyKey)
        elsif public_key.bytesize.positive?
          @public_key = T.let(RbNaCl::VerifyKey.new(public_key), RbNaCl::VerifyKey)
        else
          raise ArgumentError, "must provide one of private or public key"
        end

        super(version: "v4", purpose: "public")
      rescue RbNaCl::LengthError
        raise CryptoError, "incorrect key size"
      end

      sig { params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: "", implicit_assertion: "")
        raise ArgumentError, "no private key available" unless private_key

        m = message.to_s
        m2 = Util.pre_auth_encode(pae_header, m, footer, implicit_assertion)
        sig = T.must(private_key).sign(m2)
        payload = m + sig
        Token.new(payload:, purpose:, version:, footer:)
      end

      sig { params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: "")
        # OPTIONAL: verify footer is expected, constant-time
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        m = token.payload
        raise ParseError, "message too short" if m.size < SIGNATURE_BYTES

        s = m.slice!(-SIGNATURE_BYTES, SIGNATURE_BYTES) || ""
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
