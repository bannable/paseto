# encoding: binary
# typed: strict
# frozen_string_literal: true

module Paseto
  module Interface
    module PIE
      extend T::Sig
      extend T::Helpers

      interface!

      sig { abstract.params(header: String, data: String).returns(String) }
      def decode(header, data); end

      sig { abstract.params(key: T.untyped, nonce: T.nilable(String)).returns(String) }
      def encode(key, nonce); end
    end
  end
end
