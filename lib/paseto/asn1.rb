# typed: strict
# frozen_string_literal: true

module Paseto
  module ASN1
    # References:
    #   https://www.rfc-editor.org/rfc/rfc5208  PKCS #8: Private-Key Information Syntax Specification Version 1.2
    #   https://www.rfc-editor.org/rfc/rfc5480  Elliptic Curve Cryptography Subject Public Key Information
    #   https://www.rfc-editor.org/rfc/rfc5915  Elliptic Curve Private Key Structure
    #   https://www.rfc-editor.org/rfc/rfc5958  Asymmetric Key Packages (obsoletes PKCS#8)
    #   https://www.rfc-editor.org/rfc/rfc8018  PKCS #5: Password-Based Cryptography Specification Version 2.1
    #   https://www.secg.org/sec1-v2.pdf

    extend T::Sig

    sig { params(bytes: String).returns(String) }
    def self.p384_scalar_bytes_to_oak_der(bytes)
      OneAsymmetricKey.new(
        version: OpenSSL::BN.new(1),
        algorithm: PrivateKeyAlgorithmIdentifier.new(
          parameters: NamedCurve.new(curve_name: 'secp384r1')
        ),
        private_key: PrivateKey.new(
          private_key: ECPrivateKey.new(
            private_key: bytes
          )
        )
      ).to_der
    end

    sig { params(bytes: String).returns(String) }
    def self.ed25519_rs_to_oak_der(bytes)
      OneAsymmetricKey.new(
        version: OpenSSL::BN.new(0),
        algorithm: PrivateKeyAlgorithmIdentifier.new(
          parameters: Ed25519Identifier.new
        ),
        private_key: PrivateKey.new(
          private_key: CurvePrivateKey.new(
            private_key: T.must(bytes.byteslice(0, 32))
          )
        )
      ).to_der
    end
  end
end
