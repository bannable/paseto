# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class PrivateKey < T::Struct
      extend T::Sig

      const :private_key, T.any(ECPrivateKey, CurvePrivateKey)

      sig { returns(OpenSSL::ASN1::OctetString) }
      def build
        OpenSSL::ASN1::OctetString.new(private_key.to_der)
      end
    end
  end
end
