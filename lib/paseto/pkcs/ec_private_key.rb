# typed: strict
# frozen_string_literal: true

module Paseto
  module PKCS
    class ECPrivateKey < T::Struct
      extend T::Sig

      const :private_key, String

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::Integer.new(1),
            OpenSSL::ASN1::OctetString.new(private_key)
          ]
        )
      end

      sig { returns(String) }
      def to_der
        build.to_der
      end
    end
  end
end
