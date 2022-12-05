# typed: strict
# frozen_string_literal: true

module Paseto
  module Protocol
    class Version4
      extend T::Sig
      extend T::Helpers

      include Interface::Version

      sig(:final) { override.params(key: String, nonce: String, payload: String).returns(String) }
      def self.crypt(key:, nonce:, payload:)
        Paseto::Sodium::Stream::XChaCha20Xor.new(key).encrypt(nonce, payload)
      end

      sig(:final) { override.params(data: String, digest_size: Integer).returns(String) }
      def self.digest(data, digest_size:)
        RbNaCl::Hash.blake2b(data, digest_size: digest_size)
      end

      sig(:final) { override.returns(Integer) }
      def self.digest_bytes
        32
      end

      sig(:final) { override.params(data: String, key: String, digest_size: Integer).returns(String) }
      def self.hmac(data, key:, digest_size:)
        RbNaCl::Hash.blake2b(data, key: key, digest_size: digest_size)
      end

      sig(:final) do
        override.params(
          password: String,
          salt: String,
          length: Integer,
          parameters: T.nilable(Integer)
        ).returns(String)
      end
      def self.kdf(password, salt:, length:, **parameters)
        RbNaCl::PasswordHash.argon2id(
          password,
          salt,
          T.must(parameters[:opslimit]),
          T.must(parameters[:memlimit]),
          length
        )
      end

      sig(:final) { override.returns(String) }
      def self.paserk_version
        'k4'
      end

      sig(:final) { override.returns(String) }
      def self.pbkd_local_header
        'k4.local-pw'
      end

      sig(:final) { override.returns(String) }
      def self.pbkd_secret_header
        'k4.secret-pw'
      end

      sig(:final) { override.returns(String) }
      def self.version
        'v4'
      end
    end
  end
end
