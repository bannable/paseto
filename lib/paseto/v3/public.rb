# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module V3
    # PASETOv3 `public` token interface providing asymmetric signature signing and verification of tokens.
    class Public < AsymmetricKey
      extend T::Sig
      extend T::Helpers

      final!

      # Size of (r || s) in an ECDSA secp384r1 signature
      SIGNATURE_BYTE_LEN = 96

      # Size of r | s in an ECDSA secp384r1 signature
      SIGNATURE_PART_LEN = T.let(SIGNATURE_BYTE_LEN / 2, Integer)

      sig(:final) { override.returns(Protocol::Version3) }
      attr_reader :protocol

      # Create a new Public instance with a brand new EC key.
      sig(:final) { returns(T.attached_class) }
      def self.generate
        OpenSSL::PKey::EC.generate('secp384r1')
                         .then(&:to_der)
                         .then { |der| new(der) }
      end

      sig(:final) { params(bytes: String).returns(T.attached_class) }
      def self.from_public_bytes(bytes)
        ASN1.p384_public_bytes_to_spki_der(bytes)
            .then { |der| new(der) }
      end

      sig(:final) { params(bytes: String).returns(T.attached_class) }
      def self.from_scalar_bytes(bytes)
        ASN1.p384_scalar_bytes_to_oak_der(bytes)
            .then { |der| new(der) }
      end

      # `key` must be either a DER or PEM encoded secp384r1 key.
      # Encrypted PEM inputs are not supported.
      sig(:final) { params(key: String).void }
      def initialize(key)
        @key = T.let(OpenSSL::PKey::EC.new(key), OpenSSL::PKey::EC)
        @private = T.let(@key.private?, T::Boolean)

        raise LucidityError unless @key.group.curve_name == 'secp384r1'
        raise InvalidKeyPair unless custom_check_key

        @protocol = T.let(Protocol::Version3.instance, Protocol::Version3)

        super
      rescue OpenSSL::PKey::ECError => e
        raise CryptoError, e.message
      end

      # Sign `message` and optional non-empty `footer` and return a Token.
      # The resulting token may be bound to a particular use by passing a non-empty `implicit_assertion`.
      sig(:final) { override.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: '')
        raise ArgumentError, 'no private key available' unless private?

        Util.pre_auth_encode(public_bytes, pae_header, message, footer, implicit_assertion)
            .then { |m2| protocol.digest(m2) }
            .then { |data| @key.sign_raw(nil, data) }
            .then { |sig_asn| ASN1::ECDSASignature.from_asn1(sig_asn) }
            .then { |ecdsa_sig| ecdsa_sig.to_rs(SIGNATURE_PART_LEN) }
            .then { |sig| Token.new(payload: "#{message}#{sig}", purpose: purpose, version: version, footer: footer) }
      rescue Encoding::CompatibilityError
        raise ParseError, 'invalid message encoding, must be UTF-8'
      end

      # Verify the signature of `token`, with an optional binding `implicit_assertion`. `token` must be a `v3.public` type Token.
      # Returns the verified payload if successful, otherwise raises an exception.
      sig(:final) { override.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: '') # rubocop:disable Metrics/AbcSize
        raise LucidityError unless header == token.header

        payload = token.raw_payload
        raise ParseError, 'message too short' if payload.bytesize < SIGNATURE_BYTE_LEN

        m = T.must(payload.slice(0, payload.bytesize - SIGNATURE_BYTE_LEN))

        s = T.must(payload.slice(-SIGNATURE_BYTE_LEN, SIGNATURE_BYTE_LEN))
             .then { |bytes| ASN1::ECDSASignature.from_rs(bytes, SIGNATURE_PART_LEN).to_der }

        Util.pre_auth_encode(public_bytes, pae_header, m, token.raw_footer, implicit_assertion)
            .then { |m2| protocol.digest(m2) }
            .then { |data| @key.verify_raw(nil, s, data) }
            .then { |valid| raise InvalidSignature unless valid }
            .then { m.encode(Encoding::UTF_8) }
      rescue Encoding::UndefinedConversionError
        raise ParseError, 'invalid payload encoding'
      end

      sig(:final) { override.returns(String) }
      def public_to_pem = @key.public_to_pem

      sig(:final) { override.returns(String) }
      def private_to_pem
        raise ArgumentError, 'no private key available' unless private?

        @key.to_pem
      end

      sig(:final) { override.returns(String) }
      def to_bytes
        raise ArgumentError, 'no private key available' unless private?

        @key.private_key.to_s(2).rjust(48, "\x00")
      end

      sig(:final) { override.returns(T::Boolean) }
      def private? = @private

      sig(:final) { override.returns(String) }
      def public_bytes = @key.public_key.to_octet_string(:compressed)

      sig(:final) { override.params(other: T.any(OpenSSL::PKey::EC, OpenSSL::PKey::EC::Point)).returns(String) }
      def ecdh(other)
        case other
        when OpenSSL::PKey::EC::Point
          @key.dh_compute_key(other)
        when OpenSSL::PKey::EC
          other.dh_compute_key(@key.public_key)
        end
      end

      private

      sig(:final) { returns(T::Boolean) }
      def custom_check_key
        @key.check_key
      rescue StandardError
        false
      end
    end
  end
end
