# typed: strict
# frozen_string_literal: true

module Paseto
  module Protocol
    class Version4
      extend T::Sig
      extend T::Helpers

      include Singleton
      include Interface::Version

      sig(:final) { override.params(key: String, nonce: String, payload: String).returns(String) }
      def crypt(key:, nonce:, payload:)
        Paseto::Sodium::Stream::XChaCha20Xor.new(key).encrypt(nonce, payload)
      end

      sig(:final) { override.params(data: String, digest_size: Integer).returns(String) }
      def digest(data, digest_size: 32)
        RbNaCl::Hash.blake2b(data, digest_size: digest_size)
      end

      sig(:final) { override.returns(Integer) }
      def digest_bytes
        32
      end

      sig(:final) { override.params(data: String, key: String, digest_size: Integer).returns(String) }
      def hmac(data, key:, digest_size: 32)
        RbNaCl::Hash.blake2b(data, key: key, digest_size: digest_size)
      end

      sig(:final) { override.returns(T.class_of(Operations::ID::IDv4)) }
      def id
        Operations::ID::IDv4
      end

      sig(:final) do
        override.params(
          password: String,
          salt: String,
          length: Integer,
          parameters: T.any(Symbol, Integer)
        ).returns(String)
      end
      def kdf(password, salt:, length:, **parameters)
        memlimit = RbNaCl::PasswordHash::Argon2.memlimit_value(parameters[:memlimit])
        opslimit = RbNaCl::PasswordHash::Argon2.opslimit_value(parameters[:opslimit])

        RbNaCl::PasswordHash.argon2id(
          password,
          salt,
          opslimit,
          memlimit,
          length
        )
      end

      sig(:final) { override.returns(String) }
      def paserk_version
        'k4'
      end

      sig(:final) { override.returns(String) }
      def pbkd_local_header
        'k4.local-pw'
      end

      sig(:final) { override.returns(String) }
      def pbkd_secret_header
        'k4.secret-pw'
      end

      sig(:final) { override.params(password: String).returns(Operations::PBKD::PBKDv4) }
      def pbkw(password)
        Operations::PBKD::PBKDv4.new(password)
      end

      sig(:final) { override.params(key: SymmetricKey).returns(Wrappers::PIE::PieV4) }
      def pie(key)
        Wrappers::PIE::PieV4.new(key)
      end

      sig(:final) { override.params(key: AsymmetricKey).returns(Operations::PKE::PKEv4) }
      def pke(key)
        Operations::PKE::PKEv4.new(key)
      end

      sig(:final) { override.params(size: Integer).returns(String) }
      def random(size)
        RbNaCl::Random.random_bytes(size)
      end

      sig(:final) { override.returns(String) }
      def version
        'v4'
      end
    end
  end
end
