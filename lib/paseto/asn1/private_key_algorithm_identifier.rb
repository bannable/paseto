# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class PrivateKeyAlgorithmIdentifier < T::Struct
      extend T::Sig

      const :parameters, T.any(Ed25519Identifier, NamedCurve)

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        OpenSSL::ASN1::Sequence.new(parameters.build)
      end
    end
  end
end
