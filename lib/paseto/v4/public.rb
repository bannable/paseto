# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module V4
    # PASETOv4 `public` token interface providing asymmetric signature signing and verification of tokens.
    class Public < AsymmetricKey
      extend T::Sig
      extend T::Helpers

      final!

      # Number of bytes in an Ed25519 signature
      SIGNATURE_BYTES = 64

      sig(:final) { returns(T.any(RbNaCl::SigningKey, RbNaCl::VerifyKey)) }
      attr_reader :key

      # Create a new Public instance with a brand new Ed25519 key.
      sig(:final) { returns(T.attached_class) }
      def self.generate
        new(RbNaCl::SigningKey.generate)
      end

      sig(:final) { params(keypair: String).returns(T.attached_class) }
      def self.from_keypair(keypair)
        new(Sodium::SafeEd25519Loader.from_keypair(keypair))
      end

      sig(:final) { override.returns(Protocol::Version4) }
      def protocol
        Protocol::Version4.new
      end

      # If `key` is a String, it must be a PEM- or DER- encoded ED25519 key.
      sig(:final) { params(key: T.any(String, RbNaCl::SigningKey, RbNaCl::VerifyKey)).void }
      def initialize(key)
        key = ed25519_pkey_ossl_to_nacl(key) if key.is_a?(String)

        @key = T.let(key, T.any(RbNaCl::SigningKey, RbNaCl::VerifyKey))
      end

      # Sign `message` and optional non-empty `footer` and return a Token.
      # The resulting token may be bound to a particular use by passing a non-empty `implicit_assertion`.
      sig(:final) { override.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: '')
        raise ArgumentError, 'no private key available' unless @key.is_a?(RbNaCl::SigningKey)

        m2 = Util.pre_auth_encode(pae_header, message, footer, implicit_assertion)
        sig = @key.sign(m2)
        payload = "#{message}#{sig}"
        Token.new(payload: payload, purpose: purpose, version: version, footer: footer)
      end

      # Verify the signature of `token`, with an optional binding `implicit_assertion`. `token` must be a `v4.public`` type Token.
      # Returns the verified payload if successful, otherwise raises an exception.
      sig(:final) { override.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: '') # rubocop:disable Metrics/AbcSize
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        m = token.payload
        raise ParseError, 'message too short' if m.size < SIGNATURE_BYTES

        s = T.must(m.slice!(-SIGNATURE_BYTES, SIGNATURE_BYTES))
        m2 = Util.pre_auth_encode(pae_header, m, token.footer, implicit_assertion)

        case @key
        when RbNaCl::VerifyKey then @key.verify(s, m2)
        when RbNaCl::SigningKey then @key.verify_key.verify(s, m2)
        end

        m.encode(Encoding::UTF_8)
      rescue RbNaCl::BadSignatureError
        raise InvalidSignature
      rescue Encoding::UndefinedConversionError
        raise ParseError, 'invalid payload encoding'
      end

      sig(:final) { override.returns(String) }
      def public_to_pem
        case @key
        when RbNaCl::SigningKey
          ASN1.ed25519_pubkey_nacl_to_pem(@key.verify_key.to_bytes)
        when RbNaCl::VerifyKey
          ASN1.ed25519_pubkey_nacl_to_pem(@key.to_bytes)
        end
      end

      sig(:final) { override.returns(String) }
      def private_to_pem
        raise ArgumentError, 'no private key available' unless @key.is_a? RbNaCl::SigningKey

        ASN1.ed25519_rs_to_oak_pem(@key.keypair_bytes)
      end

      sig(:final) { override.returns(String) }
      def to_bytes
        raise ArgumentError, 'no private key available' unless @key.is_a? RbNaCl::SigningKey

        @key.keypair_bytes
      end

      sig(:final) { override.returns(T::Boolean) }
      def private?
        @key.is_a? RbNaCl::SigningKey
      end

      sig(:final) { override.returns(String) }
      def public_bytes
        case @key
        when RbNaCl::SigningKey
          @key.verify_key.to_bytes
        when RbNaCl::VerifyKey
          @key.to_bytes
        end
      end

      private

      # Convert a PEM- or DER- encoded ED25519 key into either a `RbNaCl::VerifyKey`` or `RbNaCl::SigningKey`
      sig(:final) { params(pem_or_der: String).returns(T.any(RbNaCl::VerifyKey, RbNaCl::SigningKey)) }
      def ed25519_pkey_ossl_to_nacl(pem_or_der)
        key = OpenSSL::PKey.read(pem_or_der)

        if ossl_ed25519_private_key?(key)
          bytes = OpenSSL::ASN1.decode(key.private_to_der).value[2].value[2..]
          RbNaCl::SigningKey.new(bytes)
        else
          bytes = OpenSSL::ASN1.decode(key.public_to_der).value[1].value
          RbNaCl::VerifyKey.new(bytes)
        end
      rescue OpenSSL::PKey::PKeyError => e
        raise ParseError, e.message
      end

      # ruby/openssl doesn't give us any API to detect if a PKey has a private component
      sig(:final) { params(key: OpenSSL::PKey::PKey).returns(T::Boolean) }
      def ossl_ed25519_private_key?(key)
        raise LucidityError, "expected Ed25519 key, got #{key.oid}" unless key.oid == 'ED25519'

        return false if Util.openssl?(3) && key.to_text.start_with?('ED25519 Public-Key')
        return false if Util.openssl?(1, 1, 1) && key.to_text == "<INVALID PRIVATE KEY>\n"

        true
      end
    end
  end
end
