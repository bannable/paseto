# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    class PublicKey < T::Struct
      extend T::Sig

      const :public_key, String

      sig { returns(OpenSSL::ASN1::BitString) }
      def build
        OpenSSL::ASN1::BitString.new(public_key)
      end
    end
  end
end
