# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class AlgorithmIdentifier < T::Struct
      extend T::Sig

      const :algorithm, NamedCurve

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        OpenSSL::ASN1::Sequence.new(algorithm.build)
      end
    end
  end
end
