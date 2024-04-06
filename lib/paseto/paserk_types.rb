# typed: true
# frozen_string_literal: true

module Paseto
  class PaserkTypes < T::Enum
    extend T::Sig

    enums do
      K3Local = new('k3.local')
      K3Secret = new('k3.secret')
      K3Public = new('k3.public')
      K3LocalWrap = new('k3.local-wrap')
      K3SecretWrap = new('k3.secret-wrap')
      K3LocalPBKW = new('k3.local-pw')
      K3SecretPBKW = new('k3.secret-pw')

      K4Local = new('k4.local')
      K4Secret = new('k4.secret')
      K4Public = new('k4.public')
      K4LocalWrap = new('k4.local-wrap')
      K4SecretWrap = new('k4.secret-wrap')
      K4LocalPBKW = new('k4.local-pw')
      K4SecretPBKW = new('k4.secret-pw')
    end

    sig { params(input: String).returns(Interface::Key) }
    def generate(input) # rubocop:disable Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      case self
      in K3LocalWrap | K3LocalPBKW | K3Local if input.bytesize == 32
        V3::Local.new(ikm: input)
      in K3SecretWrap | K3SecretPBKW | K3Secret if input.bytesize == 48
        V3::Public.from_scalar_bytes(input)
      in K3Public
        V3::Public.from_public_bytes(input)
      in K4LocalWrap | K4LocalPBKW | K4Local if Paseto::HAS_RBNACL && input.bytesize == 32
        V4::Local.new(ikm: input)
      in K4SecretWrap | K4SecretPBKW | K4Secret if Paseto::HAS_RBNACL && input.bytesize == 64
        V4::Public.from_keypair(input)
      in K4Public
        V4::Public.from_public_bytes(input)
      else
        raise InvalidKeyPair
      end
    end
  end
end
