# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module V3
    # PASETOv3 `public` token interface providing asymmetric signature signing and verification of tokens.
    class Public < AsymmetricKey
      extend T::Sig
      extend T::Helpers

      final!

      # Size of (r || s) in an ECDSA secp384r1 signature
      SIGNATURE_BYTE_LEN = 96

      # Size of r | s in an ECDSA secp384r1 signature
      SIGNATURE_PART_LEN = T.let(SIGNATURE_BYTE_LEN / 2, Integer)

      # Create a new Public instance with a brand new EC key.
      sig(:final) { returns(T.attached_class) }
      def self.generate
        new(key: OpenSSL::PKey::EC.generate('secp384r1').to_der)
      end

      sig(:final) { params(bytes: String).returns(T.attached_class) }
      def self.from_public_bytes(bytes)
        new(key: ASN1.p384_public_bytes_to_spki_der(bytes))
      end

      sig(:final) { params(bytes: String).returns(T.attached_class) }
      def self.from_scalar_bytes(bytes)
        new(key: ASN1.p384_scalar_bytes_to_oak_der(bytes))
      end

      sig(:final) { override.returns(Protocol::Version3) }
      def protocol
        Protocol::Version3.new
      end

      # `key` must be either a DER or PEM encoded secp384r1 key.
      # Encrypted PEM inputs are not supported.
      sig(:final) { params(key: String).void }
      def initialize(key:)
        @key = T.let(OpenSSL::PKey::EC.new(key), OpenSSL::PKey::EC)

        raise LucidityError unless @key.group.curve_name == 'secp384r1'
        raise InvalidKeyPair unless custom_check_key
      rescue OpenSSL::PKey::ECError => e
        raise CryptoError, e.message
      end

      # rubocop:disable Metrics/AbcSize

      # Sign `message` and optional non-empty `footer` and return a Token.
      # The resulting token may be bound to a particular use by passing a non-empty `implicit_assertion`.
      sig(:final) { override.params(message: String, footer: String, implicit_assertion: String).returns(Token) }
      def sign(message:, footer: '', implicit_assertion: '')
        raise ArgumentError, 'no private key available' unless private?

        m2 = Util.pre_auth_encode(public_bytes, pae_header, message, footer, implicit_assertion)

        data = OpenSSL::Digest.digest('SHA384', m2)
        sig_asn = @key.sign_raw(nil, data)
        sig = ASN1::ECDSASignature.from_asn1(sig_asn).to_rs(SIGNATURE_PART_LEN)

        payload = "#{message}#{sig}"
        Token.new(payload: payload, purpose: purpose, version: version, footer: footer)
      rescue Encoding::CompatibilityError
        raise ParseError, 'invalid message encoding, must be UTF-8'
      end

      # Verify the signature of `token`, with an optional binding `implicit_assertion`. `token` must be a `v3.public` type Token.
      # Returns the verified payload if successful, otherwise raises an exception.
      sig(:final) { override.params(token: Token, implicit_assertion: String).returns(String) }
      def verify(token:, implicit_assertion: '')
        raise ParseError, "incorrect header for key type #{header}" unless header == token.header

        m = token.payload.dup.to_s
        raise ParseError, 'message too short' if m.bytesize < SIGNATURE_BYTE_LEN

        sig = T.must(m.slice!(-SIGNATURE_BYTE_LEN, SIGNATURE_BYTE_LEN))
        s = ASN1::ECDSASignature.from_rs(sig, SIGNATURE_PART_LEN).to_der

        m2 = Util.pre_auth_encode(public_bytes, pae_header, m, token.footer, implicit_assertion)

        data = OpenSSL::Digest.digest('SHA384', m2)
        raise InvalidSignature unless @key.verify_raw(nil, s, data)

        m.encode(Encoding::UTF_8)
      rescue Encoding::UndefinedConversionError
        raise ParseError, 'invalid payload encoding'
      end

      # rubocop:enable Metrics/AbcSize

      sig(:final) { override.returns(String) }
      def public_to_pem
        @key.public_to_pem
      end

      sig(:final) { override.returns(String) }
      def private_to_pem
        raise ArgumentError, 'no private key available' unless private?

        @key.to_pem
      end

      sig(:final) { override.returns(String) }
      def to_bytes
        raise ArgumentError, 'no private key available' unless private?

        @key.private_key.to_s(2).rjust(48, "\x00")
      end

      sig(:final) { override.returns(T::Boolean) }
      def private?
        @key.private?
      end

      sig(:final) { override.returns(String) }
      def public_bytes
        @key.public_key.to_octet_string(:compressed)
      end

      sig(:final) { override.params(other: T.any(OpenSSL::PKey::EC, OpenSSL::PKey::EC::Point)).returns(String) }
      def ecdh(other)
        case other
        when OpenSSL::PKey::EC::Point
          @key.dh_compute_key(other)
        when OpenSSL::PKey::EC
          other.dh_compute_key(@key.public_key)
        end
      end

      private

      # TODO: Figure out how to get SimpleCov to cover this consistently. With OSSL1.1.1, most of
      # this doesn't run. With OSSL3, check_key never raises...
      # :nocov:

      # The openssl gem as of 3.0.0 will prefer EVP_PKEY_public_check over EC_KEY_check_key
      # whenever the EVP api is available, which is always for the library here as we're requiring
      # 3.0.0 or greater. However, this has some problems.
      #
      # The behavior of EVP_PKEY_public_check is different between 1.1.1 and 3.x. Specifically,
      # it no longer calls the custom verifier method in EVP_PKEY_METHOD, and only checks the
      # correctness of the public component. This leads to a problem when calling EC#key_check,
      # as the private component is NEVER verified for an ECDSA key through the APIs that the gem
      # makes available to us.
      #
      # Until this is fixed in ruby/openssl, I am working around this by implementing the algorithm
      # used by EVP_PKEY_pairwise_check through the OpenSSL API.
      #
      # BUG: https://github.com/ruby/openssl/issues/563
      # https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_public_check.html
      # https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_public_check.html
      sig(:final) { returns(T::Boolean) }
      def custom_check_key
        begin
          @key.check_key
        rescue StandardError
          return false
        end

        return true unless private? && Util.openssl?(3)

        priv_key = @key.private_key
        group = @key.group

        # int ossl_ec_key_private_check(const EC_KEY *eckey)
        # {
        # ...
        #   if (BN_cmp(eckey->priv_key, BN_value_one()) < 0
        #     || BN_cmp(eckey->priv_key, eckey->group->order) >= 0) {
        #     ERR_raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        #     return 0;
        #   }
        # ...
        # }
        #
        # https://github.com/openssl/openssl/blob/5ac7cfb56211d18596e3c35baa942542f3c0189a/crypto/ec/ec_key.c#L510
        # private keys must be in range [1, order-1]
        return false if priv_key < OpenSSL::BN.new(1) || priv_key > group.order

        # int ossl_ec_key_pairwise_check(const EC_KEY *eckey, BN_CTX *ctx)
        # {
        # ...
        #   if (!EC_POINT_mul(eckey->group, point, eckey->priv_key, NULL, NULL, ctx)) {
        #       ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        #       goto err;
        #   }
        #   if (EC_POINT_cmp(eckey->group, point, eckey->pub_key, ctx) != 0) {
        #       ERR_raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        #       goto err;
        #   }
        # ...
        # }
        #
        # https://github.com/openssl/openssl/blob/5ac7cfb56211d18596e3c35baa942542f3c0189a/crypto/ec/ec_key.c#L529
        # Check generator * priv_key = pub_key
        @key.public_key == group.generator.mul(priv_key)
      end

      # :nocov:
    end
  end
end
