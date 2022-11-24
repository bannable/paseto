# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class OneAsymmetricKey < T::Struct
      extend T::Sig

      const :version, OpenSSL::BN
      const :algorithm, PrivateKeyAlgorithmIdentifier
      const :private_key, PrivateKey
      const :public_key, T.nilable(PublicKey)

      sig { returns(OpenSSL::ASN1::Sequence) }
      def build
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::Integer.new(version),
            algorithm.build,
            private_key.build
            # public_key&.build
          ].compact
        )
      end

      sig { returns(String) }
      def to_der
        build.to_der
      end
    end
  end
end
