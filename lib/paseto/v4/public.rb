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

      sig(:final) { returns(T.any(RbNaCl::SigningKey, RbNaCl::VerifyKey)) }
      attr_reader :key

      # Create a new Public instance with a brand new Ed25519 key.
      sig(:final) { returns(T.attached_class) }
      def self.generate
        new(RbNaCl::SigningKey.generate)
      end

      # If `key` is a String, it must be a PEM- or DER- encoded ED25519 key.
      sig(:final) { params(key: T.any(String, RbNaCl::SigningKey, RbNaCl::VerifyKey)).void }
      def initialize(key)
        key = ed25519_pkey_ossl_to_nacl(key) if key.is_a?(String)

        @key = T.let(key, T.any(RbNaCl::SigningKey, RbNaCl::VerifyKey))

        super(version: 'v4', purpose: 'public')
      end

      # Sign `message` and optional non-empty `footer` and return a Token.
      # The resulting token may be bound to a particular use by passing a non-empty `implicit_assertion`.
      sig(:final) { override.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: '')
        raise ArgumentError, 'no private key available' unless @key.is_a?(RbNaCl::SigningKey)

        m = message
        m2 = Util.pre_auth_encode(pae_header, m, footer, implicit_assertion)
        sig = @key.sign(m2)
        payload = m + sig
        Token.new(payload: payload, purpose: purpose, version: version, footer: footer)
      end

      # Verify the signature of `token`, with an optional binding `implicit_assertion`. `token` must be a `v4.public`` type Token.
      # Returns the verified payload if successful, otherwise raises an exception.
      sig(:final) { override.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: '') # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        m = token.payload
        raise ParseError, 'message too short' if m.size < SIGNATURE_BYTES

        s = T.must(m.slice!(-SIGNATURE_BYTES, SIGNATURE_BYTES))
        m2 = Util.pre_auth_encode(pae_header, m, token.footer, implicit_assertion)

        case @key
        when RbNaCl::VerifyKey
          @key.verify(s, m2)
        when RbNaCl::SigningKey
          @key.verify_key.verify(s, m2)
        end

        m.encode!(Encoding::UTF_8)
      rescue RbNaCl::BadSignatureError
        raise InvalidSignature
      rescue Encoding::UndefinedConversionError
        raise ParseError, 'invalid payload encoding'
      end

      sig(:final) { override.returns(String) }
      def public_to_pem
        case @key
        when RbNaCl::SigningKey
          ed25519_pubkey_nacl_to_pem(@key.verify_key)
        when RbNaCl::VerifyKey
          ed25519_pubkey_nacl_to_pem(@key)
        end
      end

      sig(:final) { override.returns(String) }
      def private_to_pem
        raise ArgumentError, 'no private key available' unless @key.is_a? RbNaCl::SigningKey

        # RbNaCl::SigningKey.keypair_bytes returns the 32-byte private scalar and group element
        # as (s || g), so we repack that into an ASN1 structure and then Base64 the resulting DER
        # to get a PEM.
        kp = @key.keypair_bytes
        der = OpenSSL::ASN1::Sequence.new([
                                            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(0)),
                                            OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('ED25519')]),
                                            OpenSSL::ASN1::OctetString.new([4.chr, 32.chr, kp[0, 32]].join)
                                          ]).to_der

        <<~PEM
          -----BEGIN PRIVATE KEY-----
          #{Base64.strict_encode64(der)}
          -----END PRIVATE KEY-----
        PEM
      end

      sig(:final) { override.returns(String) }
      def to_bytes
        raise ArgumentError, 'no private key available' unless @key.is_a? RbNaCl::SigningKey

        @key.keypair_bytes
      end

      private

      sig(:final) { params(verify_key: RbNaCl::VerifyKey).returns(String) }
      def ed25519_pubkey_nacl_to_pem(verify_key)
        der = OpenSSL::ASN1::Sequence.new([
                                            OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('ED25519')]),
                                            OpenSSL::ASN1::BitString.new(verify_key.to_bytes)
                                          ]).to_der
        <<~PEM
          -----BEGIN PUBLIC KEY-----
          #{Base64.strict_encode64(der)}
          -----END PUBLIC KEY-----
        PEM
      end

      # Convert a PEM- or DER- encoded ED25519 key into either a `RbNaCl::VerifyKey`` or `RbNaCl::SigningKey`
      sig(:final) { params(pem_or_der: String).returns(T.any(RbNaCl::VerifyKey, RbNaCl::SigningKey)) }
      def ed25519_pkey_ossl_to_nacl(pem_or_der)
        key = OpenSSL::PKey.read(pem_or_der)

        if ossl_ed25519_private_key?(key)
          asn1 = OpenSSL::ASN1.decode(key.private_to_der)
          bytes = asn1.value[2].value[2..]
          RbNaCl::SigningKey.new(bytes)
        else
          asn1 = OpenSSL::ASN1.decode(key.public_to_der)
          bytes = asn1.value[1].value
          RbNaCl::VerifyKey.new(bytes)
        end
      rescue OpenSSL::PKey::PKeyError => e
        raise ParseError, e.message
      end

      # ruby/openssl doesn't give us any API to detect if a PKey has a private component
      sig(:final) { params(key: OpenSSL::PKey::PKey).returns(T::Boolean) }
      def ossl_ed25519_private_key?(key)
        raise CryptoError, "expected Ed25519 key, got #{key.oid}" unless key.oid == 'ED25519'

        return false if !Util.openssl?(3, 0, 8) && Util.openssl?(3) && key.to_text.start_with?('ED25519 Public-Key')
        return false if Util.openssl?(1, 1, 1) && key.to_text == "<INVALID PRIVATE KEY>\n"

        true
      end
    end
  end
end
