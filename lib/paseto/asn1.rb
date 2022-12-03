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
    def self.p384_public_bytes_to_spki_der(bytes)
      SubjectPublicKeyInfo.new(
        algorithm_identifier: AlgorithmIdentifier.new(
          algorithm: NamedCurve.new(curve_name: 'secp384r1')
        ),
        public_key: PublicKey.new(
          public_key: bytes
        )
      ).to_der
    end

    # RbNaCl::SigningKey.keypair_bytes returns the 32-byte private scalar and group element
    # as (s || g), so we repack that into an ASN1 structure and then Base64 the resulting DER
    # to get a PEM.
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

    sig { params(bytes: String).returns(String) }
    def self.ed25519_rs_to_oak_pem(bytes)
      der_to_private_pem(ed25519_rs_to_oak_der(bytes))
    end

    sig { params(verify_key: String).returns(String) }
    def self.ed25519_pubkey_nacl_to_der(verify_key)
      OpenSSL::ASN1::Sequence.new(
        [
          OpenSSL::ASN1::Sequence.new(
            [OpenSSL::ASN1::ObjectId.new('ED25519')]
          ),
          OpenSSL::ASN1::BitString.new(verify_key)
        ]
      ).to_der
    end

    sig { params(verify_key: String).returns(String) }
    def self.ed25519_pubkey_nacl_to_pem(verify_key)
      der_to_public_pem(ed25519_pubkey_nacl_to_der(verify_key))
    end

    sig { params(der: String).returns(String) }
    def self.der_to_public_pem(der)
      <<~PEM
        -----BEGIN PUBLIC KEY-----
        #{Base64.strict_encode64(der)}
        -----END PUBLIC KEY-----
      PEM
    end

    sig { params(der: String).returns(String) }
    def self.der_to_private_pem(der)
      <<~PEM
        -----BEGIN PRIVATE KEY-----
        #{Base64.strict_encode64(der)}
        -----END PRIVATE KEY-----
      PEM
    end
  end
end
