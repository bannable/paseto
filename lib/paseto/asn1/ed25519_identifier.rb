# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class Ed25519Identifier < T::Struct
      extend T::Sig

      sig { returns([OpenSSL::ASN1::ObjectId]) }
      def build
        [OpenSSL::ASN1::ObjectId('ED25519')]
      end
    end
  end
end
