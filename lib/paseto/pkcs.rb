# typed: strict
# frozen_string_literal: true

module Paseto
  module PKCS
    # References:
    #   https://www.rfc-editor.org/rfc/rfc5480  Elliptic Curve Cryptography Subject Public Key Information
    #   https://www.rfc-editor.org/rfc/rfc5915  Elliptic Curve Private Key Structure
    #   https://www.rfc-editor.org/rfc/rfc8018  PKCS #5: Password-Based Cryptography Specification Version 2.1
    #   https://www.secg.org/sec1-v2.pdf

    extend T::Sig

    sig { params(bytes: String).returns(String) }
    def self.p384_scalar_bytes_to_pkcs8_der(bytes)
      curve = NamedCurve.new(curve_name: 'secp384r1')
      key = ECPrivateKey.new(private_key: bytes)
      PKCS8.new(algorithm: curve, private_key: key).to_der
    end
  end
end
