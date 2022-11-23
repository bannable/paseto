# typed: strict
# frozen_string_literal: true

module Paseto
  module PKCS
    class ECDSAFullR < T::Struct
      extend T::Sig

      const :r, OpenSSL::PKey::EC::Point
      const :s, OpenSSL::BN

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::OctetString.new(r.to_octet_string(:compressed)),
            OpenSSL::ASN1::Integer.new(s)
          ]
        )
      end
    end
  end
end
