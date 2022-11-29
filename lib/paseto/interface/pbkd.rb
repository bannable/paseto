# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module PBKD
      extend T::Sig
      extend T::Helpers

      abstract!

      sig { abstract.returns(Interface::Version) }
      def protocol; end

      sig { abstract.returns(String) }
      def local_header; end

      sig { abstract.returns(String) }
      def secret_header; end

      sig { abstract.params(key: Key, options: T::Hash[T.untyped, T.untyped]).returns(String) }
      def wrap(key, options); end

      sig { abstract.params(header: String, data: String).returns(Key) }
      def unwrap(header, data); end

      sig(:final) { returns(String) }
      def version
        protocol.version
      end

      sig(:final) { returns(String) }
      def paserk_version
        protocol.paserk_version
      end
    end
  end
end
