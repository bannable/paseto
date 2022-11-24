# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class ECDSASigValue < T::Struct
      extend T::Sig

      const :r, OpenSSL::BN
      const :s, OpenSSL::BN

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::Integer.new(r),
            OpenSSL::ASN1::Integer.new(s)
          ]
        )
      end
    end
  end
end
