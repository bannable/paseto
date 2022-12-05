# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module PBKD
      extend T::Sig
      extend T::Helpers

      include Kernel

      abstract!

      module ClassMethods
        extend T::Sig
        extend T::Helpers

        interface!

        sig { abstract.returns(Interface::Version) }
        def protocol; end
      end

      mixes_in_class_methods(ClassMethods)

      sig { abstract.params(key: Key, options: T::Hash[T.untyped, T.untyped]).returns(String) }
      def wrap(key, options); end

      sig { abstract.params(header: String, data: String).returns(Key) }
      def unwrap(header, data); end

      sig(:final) { returns(String) }
      def paserk_version
        protocol.paserk_version
      end

      sig(:final) { returns(Interface::Version) }
      def protocol
        self.class.protocol
      end

      sig(:final) { returns(String) }
      def version
        protocol.version
      end
    end
  end
end
