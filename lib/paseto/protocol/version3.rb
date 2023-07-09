# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Protocol
    class Version3
      extend T::Sig
      extend T::Helpers

      include Singleton
      include Interface::Version

      sig(:final) { override.params(key: String, nonce: String, payload: String).returns(String) }
      def crypt(key:, nonce:, payload:)
        cipher = OpenSSL::Cipher.new('aes-256-ctr')
        cipher.key = key
        cipher.iv = nonce
        cipher.update(payload) + cipher.final
      end

      sig(:final) { override.params(data: String, digest_size: Integer).returns(String) }
      def digest(data, digest_size: 48)
        T.must(OpenSSL::Digest.digest('SHA384', data).byteslice(0, digest_size))
      end

      sig(:final) { override.returns(Integer) }
      def digest_bytes
        48
      end

      sig(:final) { override.params(data: String, key: String, digest_size: Integer).returns(String) }
      def hmac(data, key:, digest_size: 48)
        T.must(OpenSSL::HMAC.digest('SHA384', key, data).byteslice(0, digest_size))
      end

      sig(:final) { override.returns(T.class_of(Operations::ID::IDv3)) }
      def id
        Operations::ID::IDv3
      end

      sig(:final) do
        override.params(
          password: String,
          salt: String,
          length: Integer,
          parameters: Integer
        ).returns(String)
      end
      def kdf(password, salt:, length:, **parameters)
        OpenSSL::KDF.pbkdf2_hmac(
          password,
          salt: salt,
          length: length,
          iterations: T.must(parameters[:iterations]),
          hash: 'SHA384'
        )
      end

      sig(:final) { override.returns(String) }
      def paserk_version
        'k3'
      end

      sig(:final) { override.returns(String) }
      def pbkd_local_header
        'k3.local-pw'
      end

      sig(:final) { override.returns(String) }
      def pbkd_secret_header
        'k3.secret-pw'
      end

      sig(:final) { override.params(password: String).returns(Operations::PBKD::PBKDv3) }
      def pbkw(password)
        Operations::PBKD::PBKDv3.new(password)
      end

      sig(:final) { override.params(key: SymmetricKey).returns(Wrappers::PIE::PieV3) }
      def pie(key)
        Wrappers::PIE::PieV3.new(key)
      end

      sig(:final) { override.params(key: AsymmetricKey).returns(Operations::PKE::PKEv3) }
      def pke(key)
        Operations::PKE::PKEv3.new(key)
      end

      sig(:final) { override.params(size: Integer).returns(String) }
      def random(size)
        SecureRandom.random_bytes(size)
      end

      sig(:final) { override.returns(String) }
      def version
        'v3'
      end
    end
  end
end
