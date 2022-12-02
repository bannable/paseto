# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class SubjectPublicKeyInfo < T::Struct
      extend T::Sig

      const :algorithm_identifier, AlgorithmIdentifier
      const :public_key, PublicKey

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        OpenSSL::ASN1::Sequence.new(
          [
            algorithm_identifier.build,
            public_key.build
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
