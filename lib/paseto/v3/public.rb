# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module V3
    # PASETOv3 `public` token interface providing asymmetric signature signing and verification of tokens.
    class Public < Paseto::Key
      include IAsymmetric

      # Size of (r || s) in an ECDSA secp384r1 signature
      SIGNATURE_BYTE_LEN = 96

      # Size of r | s in an ECDSA secp384r1 signature
      SIGNATURE_PART_LEN = T.let(SIGNATURE_BYTE_LEN / 2, Integer)

      # The ECDSA secp384r1 key underlying the instance.
      sig { returns(OpenSSL::PKey::EC) }
      attr_reader :key

      # Create a new Public instance with a brand new EC key.
      sig { returns(Public) }
      def self.generate
        new(key: OpenSSL::PKey::EC.generate('secp384r1').to_der)
      end

      # `key` must be either a DER or PEM encoded secp384r1 key.
      # Encrypted PEM inputs are not supported.
      sig { params(key: String).void }
      def initialize(key:)
        # Parse the DER to an EC, then initialize an empty EC that permits only
        # secp384r1, and copy the key values from the input to the empty EC.
        # This ensures that we never accept keys that are off-curve or for groups
        # other than secp384r1.
        maybe_unsafe = OpenSSL::PKey::EC.new(key)
        @key = T.let(OpenSSL::PKey::EC.new(OpenSSL::PKey::EC::Group.new('secp384r1')), OpenSSL::PKey::EC)
        @key.private_key = maybe_unsafe.private_key
        @key.public_key = maybe_unsafe.public_key
        @key.check_key

        super(version: 'v3', purpose: 'public')
      rescue OpenSSL::PKey::ECError => e
        raise Paseto::CryptoError, e.message
      end

      # rubocop:disable Metrics/AbcSize

      # Sign `message` and optional non-empty `footer` and return a Token.
      # The resulting token may be bound to a particular use by passing a non-empty `implicit_assertion`.
      sig { override.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: '')
        raise ArgumentError, 'no private key available' unless key.private?

        pk = key.public_key.to_octet_string(:compressed)

        m2 = Util.pre_auth_encode(pk, pae_header, message, footer, implicit_assertion)

        data = OpenSSL::Digest.digest('SHA384', m2)
        sig_asn = key.sign_raw(nil, data)
        sig = asn1_to_rs(sig_asn)

        payload = message + sig
        Token.new(payload:, purpose:, version:, footer:)
      rescue Encoding::CompatibilityError
        raise Paseto::ParseError, 'invalid message encoding, must be UTF-8'
      end

      # Verify the signature of `token`, with an optional binding `implicit_assertion`. `token` must be a `v3.public` type Token.
      # Returns the verified payload if successful, otherwise raises an exception.
      sig { override.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: '')
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        m = token.payload.dup.to_s
        raise ParseError, 'message too short' if m.bytesize < SIGNATURE_BYTE_LEN

        pk = key.public_key.to_octet_string(:compressed)

        sig = m.slice!(-SIGNATURE_BYTE_LEN, SIGNATURE_BYTE_LEN) || ''
        s = rs_to_asn1(sig)

        m2 = Util.pre_auth_encode(pk, pae_header, m, token.footer, implicit_assertion)

        data = OpenSSL::Digest.digest('SHA384', m2)
        raise InvalidSignature unless key.verify_raw(nil, s, data)

        m.encode(Encoding::UTF_8)
      rescue Encoding::UndefinedConversionError
        raise Paseto::ParseError, 'invalid payload encoding'
      end

      # rubocop:enable Metrics/AbcSize

      private

      # Convert a string consisting of `(r || s)`` to a DER-encoded `ECDSA_SIG` structure
      # that can be used by OpenSSL.
      sig { params(signature: String).returns(String) }
      def rs_to_asn1(signature)
        r = signature[0, SIGNATURE_PART_LEN] || ''
        s = signature[-SIGNATURE_PART_LEN, SIGNATURE_PART_LEN] || ''
        OpenSSL::ASN1::Sequence.new(
          [r, s].map do |i|
            OpenSSL::ASN1::Integer.new(
              OpenSSL::BN.new(i, 2)
            )
          end
        ).to_der
      end

      # Convert a DER-encoded `ECDSA_SIG` structure to a binary string `(r || s)`
      # which can be encoded into our tokens.
      sig { params(signature: String).returns(String) }
      def asn1_to_rs(signature)
        OpenSSL::ASN1.decode(signature).value.map do |v|
          v.value.to_s(2).rjust(SIGNATURE_PART_LEN, "\x00")
        end.join
      end
    end
  end
end
