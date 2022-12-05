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

        sig { abstract.returns(String) }
        def paserk_version; end

        sig { abstract.returns(String) }
        def pbkd_local_header; end

        sig { abstract.returns(String) }
        def pbkd_secret_header; end

        sig { abstract.returns(String) }
        def version; end
      end

      mixes_in_class_methods(ClassMethods)

      sig { params(key: String, nonce: String, payload: String).returns(String) }
      def crypt(key:, nonce:, payload:)
        self.class.crypt(key: key, nonce: nonce, payload: payload)
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
