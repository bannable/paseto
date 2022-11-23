# typed: strict
# frozen_string_literal: true

module Paseto
  module PKCS
    class PKCS8 < T::Struct
      extend T::Sig

      const :algorithm, NamedCurve
      const :private_key, ECPrivateKey

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(0)), # version
            algorithm.build,
            OpenSSL::ASN1::OctetString.new(private_key.to_der)
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
