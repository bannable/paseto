# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class ECDSAFullR < T::Struct
      extend T::Sig

      const :r, OpenSSL::PKey::EC::Point
      const :s, OpenSSL::BN

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        # Unsupported by OpenSSL 3.0
        # :nocov:
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::OctetString.new(r.to_octet_string(:compressed)),
            OpenSSL::ASN1::Integer.new(s)
          ]
        )
        # :nocov:
      end
    end
  end
end
