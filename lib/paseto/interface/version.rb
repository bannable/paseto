# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Version
      extend T::Sig
      extend T::Helpers

      include Comparable
      include Kernel

      abstract!

      module ClassMethods
        extend T::Sig
        extend T::Helpers

        interface!

        sig { abstract.params(key: String, nonce: String, payload: String).returns(String) }
        def crypt(key:, nonce:, payload:); end

        sig { abstract.params(data: String, digest_size: Integer).returns(String) }
        def digest(data, digest_size:); end

        sig { abstract.returns(Integer) }
        def digest_bytes; end

        sig { abstract.params(data: String, key: String, digest_size: Integer).returns(String) }
        def hmac(data, key:, digest_size:); end

        sig { abstract.returns(Interface::ID) }
        def id; end

        sig do
          abstract.params(
            password: String,
            salt: String,
            length: Integer,
            parameters: Integer
          ).returns(String)
        end
        def kdf(password, salt:, length:, **parameters); end

        sig { abstract.returns(String) }
        def paserk_version; end

        sig { abstract.returns(String) }
        def pbkd_local_header; end

        sig { abstract.returns(String) }
        def pbkd_secret_header; end

        sig { abstract.params(password: String).returns(Interface::PBKD) }
        def pbkw(password); end

        sig { abstract.params(key: SymmetricKey).returns(Interface::PIE) }
        def pie(key); end

        sig { abstract.params(key: AsymmetricKey).returns(Interface::PKE) }
        def pke(key); end

        sig { abstract.params(size: Integer).returns(String) }
        def random(size); end

        sig { abstract.returns(String) }
        def version; end
      end

      mixes_in_class_methods(ClassMethods)

      sig(:final) { params(key: String, nonce: String, payload: String).returns(String) }
      def crypt(key:, nonce:, payload:)
        self.class.crypt(key: key, nonce: nonce, payload: payload)
      end

      sig(:final) { params(data: String, digest_size: T.nilable(Integer)).returns(String) }
      def digest(data, digest_size: nil)
        self.class.digest(data, digest_size: digest_size || digest_bytes)
      end

      sig(:final) { returns(Integer) }
      def digest_bytes
        self.class.digest_bytes
      end

      sig(:final) { params(data: String, key: String, digest_size: T.nilable(Integer)).returns(String) }
      def hmac(data, key:, digest_size: nil)
        self.class.hmac(data, key: key, digest_size: digest_size || digest_bytes)
      end

      sig(:final) { returns(Interface::ID) }
      def id
        self.class.id
      end

      sig(:final) do
        params(
          password: String,
          salt: String,
          length: Integer,
          parameters: Integer
        ).returns(String)
      end
      def kdf(password, salt:, length:, **parameters)
        self.class.kdf(password, salt: salt, length: length, **parameters)
      end

      sig(:final) { returns(String) }
      def paserk_version
        self.class.paserk_version
      end

      sig(:final) { returns(String) }
      def pbkd_local_header
        self.class.pbkd_local_header
      end

      sig(:final) { returns(String) }
      def pbkd_secret_header
        self.class.pbkd_secret_header
      end

      sig(:final) { params(password: String).returns(Interface::PBKD) }
      def pbkw(password)
        self.class.pbkw(password)
      end

      sig(:final) { params(key: SymmetricKey).returns(Interface::PIE) }
      def pie(key)
        self.class.pie(key)
      end

      sig(:final) { params(key: AsymmetricKey).returns(Interface::PKE) }
      def pke(key)
        self.class.pke(key)
      end

      sig(:final) { params(size: Integer).returns(String) }
      def random(size)
        self.class.random(size)
      end

      sig(:final) { returns(String) }
      def version
        self.class.version
      end

      sig(:final) { params(other: T.untyped).returns(T.nilable(Integer)) }
      def <=>(other)
        case other
        in Interface::Version
          version <=> other.version
        else
          nil
        end
      end
    end
  end
end
