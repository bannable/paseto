# encoding: binary
# frozen_string_literal: true

module Paseto
  module V3
    class Public < Paseto::Key
      # Size of (r || s) in an ECDSA secp384 signature
      SIGNATURE_BYTE_LEN = 96

      # Size of r | s in an ECDSA secp384 signature
      SIGNATURE_PART_LEN = SIGNATURE_BYTE_LEN / 2

      def self.generate
        new(private_key: OpenSSL::PKey::EC.generate("secp384r1"))
      end

      def initialize(private_key: nil, public_key: nil)
        if private_key
          raise ArgumentError, "may not provide both private and public keys" if public_key

          @key = OpenSSL::PKey::EC.new(private_key)
          @key.public_key = OpenSSL::PKey::EC.new(public_key) if public_key
        elsif public_key
          @key = OpenSSL::PKey::EC.new(public_key)
        else
          raise ArgumentError, "must provide one of private or public key"
        end

        begin
          @key.check_key
        rescue OpenSSL::PKey::ECError => e
          raise Paseto::CryptoError, e.message
        end

        super(version: "v3", purpose: "public")
      end

      def sign(message:, footer: "", implicit_assertion: "")
        raise ArgumentError, "no private key available" unless key.private?
        raise ArgumentError, "message field is mandatory" unless message

        pk = key.public_key.to_octet_string(:compressed)

        m2 = Util.pre_auth_encode(pk, pae_header, message, footer, implicit_assertion)

        data = OpenSSL::Digest.digest("SHA384", m2)
        sig_asn = key.sign_raw(nil, data)
        sig = asn1_to_rs(sig_asn)

        raise Paseto::CryptoError unless sig.bytesize == SIGNATURE_BYTE_LEN

        payload = message + sig
        Token.new(payload:, purpose:, version:, footer:)
      end

      def verify(token:, implicit_assertion: "")
        # OPTIONAL: verify footer is expected, constant-time
        raise ArgumentError, "no token" unless token
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        m = token.payload.dup.to_s
        raise ParseError, "message too short" if m.bytesize < SIGNATURE_BYTE_LEN

        pk = key.public_key.to_octet_string(:compressed)

        sig = m.slice!(-SIGNATURE_BYTE_LEN, SIGNATURE_BYTE_LEN) || ""
        s = rs_to_asn1(sig)

        m2 = Util.pre_auth_encode(pk, pae_header, m, token.footer, implicit_assertion)

        data = OpenSSL::Digest.digest("SHA384", m2)
        raise InvalidSignature unless key.verify_raw(nil, s, data)

        m
      end

      private

      attr_reader :key

      # OpenSSL returns and expects ECDSA signatures in a DER-encoded ECDSA_SIG struct,
      # but we need to be able to transport only (r || s) in big-endian form.
      # These methods allow us to convert (r ||s ) -> ECDSA_SIG and vice-versa.

      def rs_to_asn1(signature)
        r = signature[0, SIGNATURE_PART_LEN] || ""
        s = signature[-SIGNATURE_PART_LEN, SIGNATURE_PART_LEN] || ""
        OpenSSL::ASN1::Sequence.new(
          [r, s].map do |i|
            OpenSSL::ASN1::Integer.new(
              OpenSSL::BN.new(i, 2)
            )
          end
        ).to_der
      end

      def asn1_to_rs(signature)
        OpenSSL::ASN1.decode(signature).value.map do |v|
          v.value.to_s(2).rjust(SIGNATURE_PART_LEN, "\x00")
        end.join
      end
    end
  end
end
