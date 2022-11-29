# typed: true
# frozen_string_literal: true

module Paseto
  class PaserkTypes < T::Enum
    extend T::Sig

    enums do
      K3LocalWrap = new('k3.local-wrap')
      K3SecretWrap = new('k3.secret-wrap')
      K4LocalWrap = new('k4.local-wrap')
      K4SecretWrap = new('k4.secret-wrap')
      K3LocalPBKW = new('k3.local-pw')
      K3SecretPBKW = new('k3.secret-pw')
      K4LocalPBKW = new('k4.local-pw')
      K4SecretPBKW = new('k4.secret-pw')
    end

    sig { params(input: String).returns(Key) }
    def generate(input)
      case self
      in K3LocalWrap | K3LocalPBKW if input.bytesize == 32
        V3::Local.new(ikm: input)
      in K3SecretWrap | K3SecretPBKW if input.bytesize == 48
        input = ASN1.p384_scalar_bytes_to_oak_der(input)
        V3::Public.new(key: input)
      in K4LocalWrap | K4LocalPBKW if Paseto.rbnacl? && input.bytesize == 32
        V4::Local.new(ikm: input)
      in K4SecretWrap | K4SecretPBKW if Paseto.rbnacl? && input.bytesize == 64
        # TODO: Accept the public portion of this input and verify the relationship to the scalar.
        V4::Public.new(RbNaCl::SigningKey.new(input[0, 32]))
      else
        raise InvalidKeyPair
      end
    end
  end
end
