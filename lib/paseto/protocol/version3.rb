# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Protocol
    class Version3
      extend T::Sig
      extend T::Helpers

      include Interface::Version

      sig(:final) { override.params(key: String, nonce: String, payload: String).returns(String) }
      def self.crypt(key:, nonce:, payload:)
        cipher = OpenSSL::Cipher.new('aes-256-ctr')
        cipher.key = key
        cipher.iv = nonce
        cipher.update(payload) + cipher.final
      end

      sig(:final) { override.params(data: String, digest_size: Integer).returns(String) }
      def self.digest(data, digest_size:)
        T.must(OpenSSL::Digest.digest('SHA384', data).byteslice(0, digest_size))
      end

      sig(:final) { override.returns(Integer) }
      def self.digest_bytes
        48
      end

      sig(:final) { override.params(data: String, key: String, digest_size: Integer).returns(String) }
      def self.hmac(data, key:, digest_size:)
        T.must(OpenSSL::HMAC.digest('SHA384', key, data).byteslice(0, digest_size))
      end

      sig(:final) do
        override.params(
          password: String,
          salt: String,
          length: Integer,
          parameters: Integer
        ).returns(String)
      end
      def self.kdf(password, salt:, length:, **parameters)
        OpenSSL::KDF.pbkdf2_hmac(
          password,
          salt: salt,
          length: length,
          iterations: T.must(parameters[:iterations]),
          hash: 'SHA384'
        )
      end

      sig(:final) { override.returns(String) }
      def self.paserk_version
        'k3'
      end

      sig(:final) { override.returns(String) }
      def self.pbkd_local_header
        'k3.local-pw'
      end

      sig(:final) { override.returns(String) }
      def self.pbkd_secret_header
        'k3.secret-pw'
      end

      sig(:final) { override.params(key: SymmetricKey).returns(Wrappers::PIE::PieV3) }
      def self.pie(key)
        Wrappers::PIE::PieV3.new(key)
      end

      sig(:final) { override.params(key: AsymmetricKey).returns(Operations::PKE::PKEv3) }
      def self.pke(key)
        Operations::PKE::PKEv3.new(key)
      end

      sig(:final) { override.params(size: Integer).returns(String) }
      def self.random(size)
        SecureRandom.random_bytes(size)
      end

      sig(:final) { override.returns(String) }
      def self.version
        'v3'
      end
    end
  end
end
