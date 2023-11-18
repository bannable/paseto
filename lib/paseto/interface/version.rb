# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module Version
      extend T::Sig
      extend T::Helpers

      include Comparable

      abstract!

      sig { abstract.params(key: String, nonce: String, payload: String).returns(String) }
      def crypt(key:, nonce:, payload:); end

      sig { abstract.params(data: String, digest_size: Integer).returns(String) }
      def digest(data, digest_size:); end

      sig { abstract.returns(Integer) }
      def digest_bytes; end

      sig { abstract.params(data: String, key: String, digest_size: Integer).returns(String) }
      def hmac(data, key:, digest_size: nil); end

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
