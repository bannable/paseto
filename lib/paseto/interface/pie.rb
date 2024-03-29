# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module PIE
      extend T::Sig
      extend T::Helpers

      abstract!

      sig { abstract.params(nonce: String).returns(String) }
      def authentication_key(nonce:); end

      sig { abstract.params(payload: String, auth_key: String).returns(String) }
      def authentication_tag(payload:, auth_key:); end

      sig { abstract.params(nonce: String, payload: String).returns(String) }
      def crypt(nonce:, payload:); end

      sig { abstract.params(data: String).returns({ t: String, n: String, c: String }) }
      def decode_and_split(data); end

      sig { abstract.returns(String) }
      def local_header; end

      sig { abstract.returns(Interface::Version) }
      def protocol; end

      sig { abstract.returns(String) }
      def random_nonce; end

      sig { abstract.returns(String) }
      def secret_header; end
    end
  end
end
