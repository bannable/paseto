# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class CurvePrivateKey < T::Struct
      extend T::Sig

      const :private_key, String

      sig { returns(OpenSSL::ASN1::OctetString) }
      def build
        OpenSSL::ASN1::OctetString.new(private_key)
      end

      sig { returns(String) }
      def to_der
        build.to_der
      end
    end
  end
end
