# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class ECDSASignature < T::Struct
      extend T::Sig

      const :signature, T.any(ECDSASigValue, ECDSAFullR)

      sig { params(bytes: String, part_len: Integer).returns(ECDSASignature) }
      def self.from_rs(bytes, part_len)
        r = OpenSSL::BN.new(T.must(bytes[0, part_len]), 2)
        s = OpenSSL::BN.new(T.must(bytes[-part_len, part_len]), 2)
        new(signature: ECDSASigValue.new(r:, s:))
      end

      sig { params(sig: String).returns(ECDSASignature) }
      def self.from_asn1(sig)
        r, s = OpenSSL::ASN1.decode(sig).value.map(&:value)
        new(signature: ECDSASigValue.new(r:, s:))
      end

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        signature.build
      end

      sig { returns(String) }
      def to_der
        build.to_der
      end

      sig { params(part_len: Integer).returns(String) }
      def to_rs(part_len)
        case signature
        when ECDSASigValue
          r = T.cast(signature.r, OpenSSL::BN).to_s(2).rjust(part_len, "\x00")
        when ECDSAFullR
          # :nocov:
          r = T.cast(signature.r, OpenSSL::PKey::EC::Point).to_octet_string(:compressed).rjust(part_len, "\x00")
          # :nocov:
        end
        s = signature.s.to_s(2).rjust(part_len, "\x00")
        [r, s].join
      end
    end
  end
end
