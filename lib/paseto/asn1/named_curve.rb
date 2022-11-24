# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class NamedCurve < T::Struct
      extend T::Sig

      const :curve_name, String

      sig { returns([OpenSSL::ASN1::ObjectId, OpenSSL::ASN1::ObjectId]) }
      def build
        [OpenSSL::ASN1::ObjectId('id-ecPublicKey'), OpenSSL::ASN1::ObjectId(curve_name)]
      end
    end
  end
end
