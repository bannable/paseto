# typed: strict
# frozen_string_literal: true

module Paseto
  module PKCS
    class NamedCurve < T::Struct
      extend T::Sig

      const :curve_name, String

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'),
            OpenSSL::ASN1::ObjectId.new(curve_name)
          ]
        )
      end
    end
  end
end
